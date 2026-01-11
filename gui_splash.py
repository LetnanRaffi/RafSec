"""
RafSec - Splash Screen
=======================
Cinematic loading screen with progress animation.

Author: RafSec Team
"""

import customtkinter as ctk
import threading
import time
import random


class SplashScreen(ctk.CTkToplevel):
    """
    Animated splash screen shown during startup.
    
    Features:
    - No window decorations (borderless)
    - Animated progress bar
    - Dynamic loading messages
    """
    
    LOADING_MESSAGES = [
        "Initializing neural engine...",
        "Loading YARA signatures...",
        "Mounting secure vault...",
        "Calibrating threat sensors...",
        "Connecting to cloud intelligence...",
        "Activating live protection...",
        "Scanning system integrity...",
        "Loading machine learning models...",
        "Preparing security modules...",
        "Starting RafSec Engine...",
    ]
    
    def __init__(self, parent=None, duration: float = 3.5):
        """
        Create splash screen.
        
        Args:
            parent: Parent window (can be None)
            duration: How long to show splash (seconds)
        """
        super().__init__(parent)
        
        self.duration = duration
        self._progress = 0.0
        self._running = True
        
        # Configure window
        self.overrideredirect(True)  # Remove window decorations
        self.configure(fg_color='#0d0d0d')
        
        # Size and center
        width = 500
        height = 300
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")
        
        # Keep on top
        self.attributes('-topmost', True)
        
        # Build UI
        self._create_widgets()
        
        # Start animation
        self._animate_thread = threading.Thread(target=self._animate, daemon=True)
        self._animate_thread.start()
    
    def _create_widgets(self):
        """Create splash screen widgets."""
        # Main frame
        frame = ctk.CTkFrame(self, fg_color='#0d0d0d', corner_radius=0)
        frame.pack(fill='both', expand=True, padx=2, pady=2)
        
        # Logo text
        logo_frame = ctk.CTkFrame(frame, fg_color='transparent')
        logo_frame.pack(expand=True)
        
        # Shield icon
        ctk.CTkLabel(
            logo_frame,
            text="◆",
            font=ctk.CTkFont(size=80, weight="bold"),
            text_color='#cf1020'
        ).pack()
        
        # App name
        ctk.CTkLabel(
            logo_frame,
            text="RAFSEC",
            font=ctk.CTkFont(family="Arial", size=36, weight="bold"),
            text_color='#ffffff'
        ).pack()
        
        ctk.CTkLabel(
            logo_frame,
            text="SECURITY SUITE",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color='#888888'
        ).pack()
        
        # Version
        ctk.CTkLabel(
            logo_frame,
            text="v3.0 PREMIUM",
            font=ctk.CTkFont(size=10),
            text_color='#cf1020'
        ).pack(pady=(10, 0))
        
        # Bottom section
        bottom = ctk.CTkFrame(frame, fg_color='transparent')
        bottom.pack(fill='x', side='bottom', pady=30, padx=40)
        
        # Loading message
        self.loading_label = ctk.CTkLabel(
            bottom,
            text="Initializing...",
            font=ctk.CTkFont(size=11),
            text_color='#888888'
        )
        self.loading_label.pack(pady=(0, 10))
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(
            bottom,
            mode='determinate',
            progress_color='#cf1020',
            fg_color='#2b2b2b',
            height=6,
            corner_radius=3
        )
        self.progress_bar.pack(fill='x')
        self.progress_bar.set(0)
    
    def _animate(self):
        """Run loading animation."""
        start_time = time.time()
        message_idx = 0
        
        while self._running:
            elapsed = time.time() - start_time
            progress = min(elapsed / self.duration, 1.0)
            
            # Update progress
            self._progress = progress
            self.after(0, lambda p=progress: self.progress_bar.set(p))
            
            # Update message periodically
            if elapsed > (message_idx + 1) * (self.duration / len(self.LOADING_MESSAGES)):
                message_idx = min(message_idx + 1, len(self.LOADING_MESSAGES) - 1)
                msg = self.LOADING_MESSAGES[message_idx]
                self.after(0, lambda m=msg: self.loading_label.configure(text=m))
            
            # Check if done
            if progress >= 1.0:
                time.sleep(0.3)  # Brief pause at 100%
                self._running = False
                self.after(0, self._finish)
                break
            
            time.sleep(0.05)
    
    def _finish(self):
        """Close splash screen."""
        try:
            self.destroy()
        except:
            pass
    
    def wait(self):
        """Wait for splash to complete."""
        if self._animate_thread:
            self._animate_thread.join()


def show_splash(duration: float = 3.5) -> SplashScreen:
    """
    Show splash screen.
    
    Args:
        duration: Display duration in seconds
        
    Returns:
        SplashScreen instance
    """
    splash = SplashScreen(duration=duration)
    return splash
