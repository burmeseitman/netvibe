"""
local_ai.py - Local AI Security Analyst powered by llama.cpp

This module loads a quantized GGUF model and provides a conversational
interface to analyze network alerts and suggest mitigation strategies.
"""

import os
import logging
import asyncio
from pathlib import Path

logger = logging.getLogger(__name__)

# Default model path. Configurable via environment variable.
DEFAULT_MODEL_PATH = Path("d:/AgentCode/netvibe/models/Meta-Llama-3-8B-Instruct-Q4_K_M.gguf")
MODEL_PATH = os.getenv("NETVIBE_AI_MODEL_PATH", str(DEFAULT_MODEL_PATH))

class LlamaAnalyst:
    def __init__(self):
        self._llm = None
        self._loading = False
        self._failed = False

    def _ensure_loaded(self):
        if self._llm is not None:
            return True
        if self._failed:
            return False
            
        try:
            logger.info(f"Loading local AI model from: {MODEL_PATH}")
            # Import dynamically so the rest of the app isn't blocked if missing
            from llama_cpp import Llama
            self._llm = Llama(
                model_path=str(MODEL_PATH),
                n_ctx=2048,           # Context window
                n_threads=4,          # CPU threads
                verbose=False         # Suppress excessive llama.cpp logs
            )
            logger.info("Local AI model loaded successfully.")
            return True
        except ImportError:
            logger.error("llama-cpp-python is not installed. Run 'pip install llama-cpp-python'")
            self._failed = True
            return False
        except Exception as e:
            logger.error(f"Failed to load AI model: {e}")
            self._failed = True
            return False

    def _generate_report_sync(self, prompt: str) -> str:
        """Synchronous wrapper for Llama inference."""
        if not self._ensure_loaded():
            return "❌ AI Analyst Unavailable: Model failed to load or `llama-cpp-python` is missing."
        
        system_prompt = (
            "You are an Elite SOC Analyst for NetVibe AI Traffic Monitor. "
            "Write a concise, professional security analysis for the following incident data. "
            "Suggest immediate mitigation steps."
        )

        formatted_msg = f"<|start_header_id|>system<|end_header_id|>\n{system_prompt}<|eot_id|>\n"
        formatted_msg += f"<|start_header_id|>user<|end_header_id|>\n{prompt}<|eot_id|>\n"
        formatted_msg += "<|start_header_id|>assistant<|end_header_id|>\n"

        response = self._llm(
            formatted_msg,
            max_tokens=256,
            stop=["<|eot_id|>"],
            temperature=0.3
        )
        return response["choices"][0]["text"].strip()

    async def analyze_incident(self, incident_title: str, incident_desc: str, alerts_summary: str) -> str:
        """Asynchronously analyze an incident so we don't block the FastAPI event loop."""
        prompt = (
            f"Incident Title: {incident_title}\n"
            f"Description: {incident_desc}\n\n"
            f"Alerts Summary:\n{alerts_summary}\n\n"
            "Provide an analysis and mitigation steps."
        )
        # Run inference in a separate thread
        result = await asyncio.to_thread(self._generate_report_sync, prompt)
        return result

# Global singleton
analyst_engine = LlamaAnalyst()

# --- End of local_ai.py ---
