import os
import glob
from typing import List, Dict, Any
from pathlib import Path
import logging
import snowflake.connector
from dotenv import load_dotenv

from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import TextLoader, PyPDFLoader, UnstructuredMarkdownLoader

logger = logging.getLogger(__name__)
load_dotenv()

class RAGManager:
    """
    Manages the RAG system using SNOWFLAKE as the Vector Database.
    Indexes documents into LLMCHECK_DB.RAG.DOCUMENT_CHUNKS.
    Uses Snowflake Cortex for Embeddings (Arctic) and Generation.
    """
    
    def __init__(self, knowledge_base_dir: str = "knowledge_base"):
        self.kb_dir = knowledge_base_dir
        self.conn = None
        
        # Ensure KB directory exists
        if not os.path.exists(self.kb_dir):
            os.makedirs(self.kb_dir)
            
        self._connect_snowflake()

    def _connect_snowflake(self):
        """Establish connection to Snowflake."""
        try:
            self.conn = snowflake.connector.connect(
                user=os.getenv("SNOWFLAKE_USER"),
                password=os.getenv("SNOWFLAKE_PASSWORD"),
                account=os.getenv("SNOWFLAKE_ACCOUNT"),
                warehouse=os.getenv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
                database="LLMCHECK_DB",
                schema="RAG"
            )
            logger.info("Connected to Snowflake for RAG.")
        except Exception as e:
            logger.error(f"Snowflake Connection Failed: {e}")
            self.conn = None

    def list_documents(self) -> List[str]:
        """
        List all unique documents currently stored in the Knowledge Base.
        """
        if not self.conn:
            return []
        
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT DISTINCT SOURCE_FILE FROM LLMCHECK_DB.RAG.DOCUMENT_CHUNKS ORDER BY SOURCE_FILE")
            return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to list documents: {e}")
            return []
        finally:
            cursor.close()

    def add_document(self, file_content: bytes, filename: str, progress_callback=None) -> str:
        """
        Add a new document to the Snowflake Vector Store.
        Uses a temporary file for processing, then deletes it.
        """
        if not self.conn:
            return "Snowflake connection not available."

        import tempfile
        
        cursor = self.conn.cursor()
        temp_path = None
        
        try:
            # 1. Save to Temp File
            suffix = Path(filename).suffix
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(file_content)
                temp_path = tmp.name
            
            # 2. Check if already exists (optional: currently we duplicate or we can delete first)
            # Let's delete existing versions of this file to ensure clean update
            if progress_callback: progress_callback(0.1, "Cleaning old versions...")
            self.delete_document(filename)

            # 3. Load & Split
            if progress_callback: progress_callback(0.2, "Parsing document...")
            if suffix.lower() == '.pdf': loader = PyPDFLoader(temp_path)
            elif suffix.lower() == '.md': loader = UnstructuredMarkdownLoader(temp_path)
            else: loader = TextLoader(temp_path)
            
            documents = loader.load()
            for doc in documents:
                doc.metadata['source'] = filename  # Use original filename, not temp path
                
            text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
            chunks = text_splitter.split_documents(documents)
            
            # 4. Insert Embeddings (Batch Processing)
            total_chunks = len(chunks)
            batch_size = 50 # Increased for speed
            count = 0
            
            if progress_callback: progress_callback(0.3, f"Embedding {total_chunks} chunks...")

            for i in range(0, total_chunks, batch_size):
                batch = chunks[i:i + batch_size]
                values_list = []
                
                for chunk in batch:
                    # Sanitize text
                    text = chunk.page_content.replace("'", "''").replace("\\", "\\\\")
                    source = chunk.metadata.get('source', 'unknown').replace("'", "''")
                    values_list.append(f"('{text}', '{source}')")
                
                if not values_list:
                    continue
                    
                values_str = ",".join(values_list)
                
                # Single optimization query per batch
                query = f"""
                INSERT INTO LLMCHECK_DB.RAG.DOCUMENT_CHUNKS (CHUNK_TEXT, EMBEDDING, SOURCE_FILE)
                SELECT 
                    column1,
                    SNOWFLAKE.CORTEX.EMBED_TEXT_768('snowflake-arctic-embed-m', column1),
                    column2
                FROM VALUES {values_str}
                """
                
                cursor.execute(query)
                count += len(batch)
                
                # Update progress
                if progress_callback:
                    # Scale remaining 70% of progress over the chunks
                    current_progress = 0.3 + (0.7 * (min(i + batch_size, total_chunks) / total_chunks))
                    progress_callback(current_progress, f"Indexed {min(i + batch_size, total_chunks)}/{total_chunks} chunks")
                
            return f"✅ Added '{filename}' ({count} chunks)."
            
        except Exception as e:
            return f"Failed to add document: {str(e)}"
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
            cursor.close()

    def delete_document(self, filename: str) -> str:
        """
        Remove a document from the Snowflake Vector Store.
        """
        if not self.conn:
            return "Snowflake connection not available."
            
        cursor = self.conn.cursor()
        try:
            escaped_name = filename.replace("'", "''")
            cursor.execute(f"DELETE FROM LLMCHECK_DB.RAG.DOCUMENT_CHUNKS WHERE SOURCE_FILE = '{escaped_name}'")
            return f"🗑️ Deleted '{filename}'."
        except Exception as e:
            return f"Failed to delete: {e}"
        finally:
            cursor.close()

    def retrieve_context(self, query: str) -> tuple[str, List[str]]:
        """
        Retrieve relevant context blocks from Snowflake without generating an answer.
        Returns: (formatted_string, list_of_unique_sources)
        """
        if not self.conn:
            return ("", [])
            
        cursor = self.conn.cursor()
        try:
            escaped_q = query.replace("'", "''")
            
            search_sql = f"""
            SELECT CHUNK_TEXT, SOURCE_FILE
            FROM LLMCHECK_DB.RAG.DOCUMENT_CHUNKS
            ORDER BY VECTOR_COSINE_SIMILARITY(
                SNOWFLAKE.CORTEX.EMBED_TEXT_768('snowflake-arctic-embed-m', '{escaped_q}'),
                EMBEDDING
            ) DESC
            LIMIT 4
            """
            
            cursor.execute(search_sql)
            results = cursor.fetchall()
            
            if not results:
                return ("", [])
                
            # Combine Context with Source Attribution
            context_blocks = []
            sources = set()
            
            for row in results:
                text = row[0]
                source = row[1]
                sources.add(source)
                context_blocks.append(f"Source: {source}\nContent: {text}")
                
            return ("\n\n---\n\n".join(context_blocks), list(sources))
            
        except Exception as e:
            logger.error(f"Context retrieval failed: {e}")
            return ("", [])
        finally:
            cursor.close()

    def query(self, user_question: str) -> str:
        """
        RAG Query: Returns answer based on context.
        """
        if not self.conn:
            return "Snowflake connection lost."
            
        cursor = self.conn.cursor()
        try:
            # 1. Retrieve Context
            context_str = self.retrieve_context(user_question)
            
            if not context_str:
                return "I couldn't find any relevant information in the Knowledge Base."
            
            # 2. Generate Answer using Cortex Complete
            # Optimized prompt for RAG
            prompt = f"""
            You are a strict security compliance assistant. 
            
            INSTRUCTIONS:
            1. Answer the question based ONLY on the context provided below.
            2. Do NOT use outside knowledge.
            3. If the answer is not contained within the provided context, state: "I do not know the answer based on the provided documents."
            4. CITE YOUR SOURCES. For every fact you state, mention the source file name provided in the context.
            
            Key Information Context:
            {context_str}
            
            User Question: 
            {user_question}
            
            Answer:
            """
            
            # Call Cortex Complete with Temperature 0
            escaped_prompt = prompt.replace("'", "''")
            
            complete_sql = f"""
            SELECT SNOWFLAKE.CORTEX.COMPLETE(
                'mistral-large', 
                '{escaped_prompt}',
                {{'temperature': 0.0}}
            )
            """
            cursor.execute(complete_sql)
            answer_row = cursor.fetchone()
            
            if answer_row:
                return answer_row[0]
            else:
                return "Failed to generate answer."
                
        except Exception as e:
            return f"Query Error: {str(e)}"
        finally:
            cursor.close()
