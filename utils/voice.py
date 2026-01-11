"""
RafSec Utils - Voice Alerts
============================
Text-to-speech for security alerts.

Author: RafSec Team
"""

import threading
from typing import Optional

try:
    import pyttsx3
    TTS_AVAILABLE = True
except ImportError:
    TTS_AVAILABLE = False


class VoiceAlert:
    """
    Text-to-speech voice alerts.
    
    Provides spoken feedback for security events.
    Runs in separate thread to avoid blocking UI.
    """
    
    _engine: Optional[object] = None
    _lock = threading.Lock()
    _enabled = True
    
    @classmethod
    def _get_engine(cls):
        """Get or create TTS engine."""
        if not TTS_AVAILABLE:
            return None
        
        with cls._lock:
            if cls._engine is None:
                try:
                    cls._engine = pyttsx3.init()
                    # Configure voice
                    cls._engine.setProperty('rate', 150)  # Speed
                    cls._engine.setProperty('volume', 0.9)  # Volume
                except Exception:
                    pass
        
        return cls._engine
    
    @classmethod
    def speak(cls, text: str, block: bool = False):
        """
        Speak text aloud.
        
        Args:
            text: Text to speak
            block: If True, wait for speech to complete
        """
        if not cls._enabled or not TTS_AVAILABLE:
            return
        
        def _speak():
            try:
                engine = cls._get_engine()
                if engine:
                    with cls._lock:
                        engine.say(text)
                        engine.runAndWait()
            except Exception:
                pass
        
        if block:
            _speak()
        else:
            thread = threading.Thread(target=_speak, daemon=True)
            thread.start()
    
    @classmethod
    def set_enabled(cls, enabled: bool):
        """Enable or disable voice alerts."""
        cls._enabled = enabled
    
    @classmethod
    def is_enabled(cls) -> bool:
        """Check if voice alerts are enabled."""
        return cls._enabled and TTS_AVAILABLE
    
    @classmethod
    def is_available(cls) -> bool:
        """Check if TTS is available."""
        return TTS_AVAILABLE
    
    # Predefined alerts
    @classmethod
    def alert_scan_start(cls):
        cls.speak("Scanning system.")
    
    @classmethod
    def alert_scan_complete_clean(cls):
        cls.speak("Scan complete. System is secure.")
    
    @classmethod
    def alert_threat_detected(cls):
        cls.speak("Warning! Threat detected!")
    
    @classmethod
    def alert_ransomware(cls):
        cls.speak("Critical alert! Ransomware activity detected!")
    
    @classmethod
    def alert_file_encrypted(cls):
        cls.speak("File encrypted and secured.")
    
    @classmethod
    def alert_file_decrypted(cls):
        cls.speak("File decrypted successfully.")
    
    @classmethod
    def alert_live_protection_on(cls):
        cls.speak("Live protection enabled.")
    
    @classmethod
    def alert_live_protection_off(cls):
        cls.speak("Live protection disabled.")
    
    @classmethod
    def alert_cleanup_complete(cls, space_freed: str):
        cls.speak(f"Cleanup complete. {space_freed} freed.")
