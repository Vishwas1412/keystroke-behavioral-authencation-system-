import keyboard
import time
import pickle
import tkinter as tk
from tkinter import messagebox, simpledialog
import threading
import numpy as np
from sklearn.ensemble import IsolationForest
import hashlib
import os
import json
import datetime
import ctypes  # For screen control on Windows
import subprocess  # For screen control on macOS/Linux
import platform  # To detect OS

class KeystrokeBehavioralAuthSystem:
    def __init__(self):
        # User profile storage
        self.user_profiles = {}
        self.current_user = None
        
        # Security logging
        self.security_log = []
        self.last_known_user = None
        self.suspicious_attempts = {}
        
        # Monitoring state
        self.is_monitoring = False
        self.auth_thread = None
        
        # Collection parameters
        self.keystroke_data = []
        self.keystroke_combinations = []  # For specific key combinations
        self.login_keystroke_data = []  # For login verification
        
        # Timing parameters
        self.last_key_time = None
        self.last_key = None
        
        # Anomaly detection model
        self.keystroke_model = IsolationForest(contamination=0.1, random_state=42)
        
        # Authentication parameters
        self.auth_check_interval = 5  # seconds between auth checks (reduced from 10)
        self.anomaly_threshold = -0.3  # threshold for anomaly score
        self.login_anomaly_threshold = -0.4  # stricter threshold during login
        self.verification_required = False
        self.min_keystrokes_for_check = 5  # Minimum keystrokes needed for authentication check
        self.system_locked = False
        
        # Privacy protection features
        self.screen_protected = False
        self.continuous_anomaly_check = True
        self.quick_check_interval = 2  # seconds for quick check when in protected mode
        self.privacy_protection_level = 1  # 1 = screen off, 2 = screen off + lock, 3 = screen off + lock + alert
        self.consecutive_anomalies_for_protection = 1  # Trigger privacy protection after this many anomalies
        self.consecutive_anomalies = 0  # Counter for anomalies
        
        # Try to load existing profiles
        try:
            with open('user_profiles.pkl', 'rb') as f:
                self.user_profiles = pickle.load(f)
            print(f"Loaded {len(self.user_profiles)} user profiles")
        except FileNotFoundError:
            print("No existing profiles found, starting fresh")
            
        # Try to load security log
        try:
            with open('security_log.json', 'r') as f:
                self.security_log = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.security_log = []
    
    def _hash_password(self, password, salt=None):
        """Hash password with salt for secure storage"""
        if salt is None:
            salt = os.urandom(32)  # Generate random salt
        
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000  # Number of iterations
        )
        
        return salt, key
    
    def _verify_password(self, stored_salt, stored_key, provided_password):
        """Verify password against stored hash"""
        _, key = self._hash_password(provided_password, stored_salt)
        return key == stored_key
    
    def _log_security_event(self, event_type, username, details=None):
        """Log security events for audit"""
        timestamp = datetime.datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "username": username,
            "details": details or {}
        }
        self.security_log.append(log_entry)
        
        # Keep only the last 1000 entries
        if len(self.security_log) > 1000:
            self.security_log = self.security_log[-1000:]
            
        # Save log to disk
        with open('security_log.json', 'w') as f:
            json.dump(self.security_log, f)
            
        print(f"Security event logged: {event_type} for {username}")
    
    def start_enrollment(self, username, password, duration=60):
        """Begin collecting user behavioral data for enrollment"""
        print(f"Starting enrollment for user {username} for {duration} seconds")
        
        # Check if username already exists
        if username in self.user_profiles:
            print(f"User {username} already exists. Please use a different username or reset the profile.")
            return False
        
        # Store username and hashed password
        salt, key = self._hash_password(password)
        
        self.current_user = username
        self.keystroke_data = []
        self.keystroke_combinations = []
        
        # Register hook for data collection
        keyboard.hook(self._on_key_event)
        
        # Collect data for specified duration
        start_time = time.time()
        end_time = start_time + duration
        
        print("Please type naturally to create your behavioral profile...")
        while time.time() < end_time:
            remaining = int(end_time - time.time())
            if remaining % 10 == 0 and remaining > 0:
                print(f"{remaining} seconds remaining... ({len(self.keystroke_data)} samples collected)")
            time.sleep(0.1)
        
        # Unhook data collection
        keyboard.unhook_all()
        
        # Check if enough data was collected
        if len(self.keystroke_data) < 20:
            print("Not enough keystroke data collected. Please try again and type more.")
            return False
        
        # Train model on collected data
        self._train_model()
        
        # Save user profile
        self.user_profiles[username] = {
            'keystroke_model': self.keystroke_model,
            'timestamp': time.time(),
            'password_salt': salt,
            'password_key': key,
            'sample_size': len(self.keystroke_data),
            'enrollment_data': self.keystroke_data[:100]  # Save some enrollment data for comparison
        }
        
        # Save profiles to disk
        with open('user_profiles.pkl', 'wb') as f:
            pickle.dump(self.user_profiles, f)
        
        # Log enrollment
        self._log_security_event("enrollment", username, {
            "samples": len(self.keystroke_data),
            "time": datetime.datetime.now().isoformat()
        })
        
        print(f"Enrollment complete for {username} with {len(self.keystroke_data)} keystroke samples")
        return True
    
    def start_login_keystroke_collection(self, username):
        """Begin collecting keystrokes during login attempt for verification"""
        print("Collecting keystroke data during password entry...")
        self.login_keystroke_data = []
        keyboard.hook(self._on_login_key_event)
        return True
    
    def stop_login_keystroke_collection(self):
        """Stop collecting keystrokes during login"""
        keyboard.unhook_all()
        return True
    
    def _on_login_key_event(self, event):
        """Handle keyboard events during login"""
        if event.event_type == keyboard.KEY_DOWN:
            current_time = time.time()
            current_key = event.name
            
            # Basic keystroke timing
            if self.last_key_time is not None:
                # Calculate time between keystrokes
                time_diff = current_time - self.last_key_time
                
                # Only record reasonable timing differences (0.01s to 2.5s)
                if 0.01 <= time_diff <= 2.5:
                    # Store both timing and key transition
                    feature = [time_diff]
                    
                    key_transition_hash = hash(f"{self.last_key}_{current_key}") % 1000
                    feature.append(key_transition_hash / 1000)
                    
                    self.login_keystroke_data.append(feature)
            
            self.last_key_time = current_time
            self.last_key = current_key
    
    def verify_keystroke_pattern(self, username):
        """Verify if login keystroke pattern matches enrolled user"""
        if len(self.login_keystroke_data) < 5:
            print("Not enough keystroke data collected during login for verification")
            return True  # Default to password-only auth if not enough data
            
        if username not in self.user_profiles:
            return False
            
        user_model = self.user_profiles[username]['keystroke_model']
        
        # Analyze login keystroke pattern
        X_login = np.array(self.login_keystroke_data)
        try:
            login_scores = user_model.decision_function(X_login)
            login_avg_score = np.mean(login_scores)
            
            print(f"Login keystroke verification score: {login_avg_score:.2f}")
            
            # Use stricter threshold for login verification
            if login_avg_score < self.login_anomaly_threshold:
                print("WARNING: Login keystroke pattern does not match enrolled user!")
                return False
            else:
                print("Login keystroke pattern matches enrolled user")
                return True
        except Exception as e:
            print(f"Error during keystroke pattern verification: {e}")
            return True  # Fall back to password-only auth on error
    
    def start_monitoring(self, username, password):
        """Begin continuous authentication monitoring with password verification"""
        if username not in self.user_profiles:
            print(f"User {username} not found in profiles")
            self._log_security_event("login_attempt_unknown_user", username)
            return False
        
        # Start capturing keystrokes for login verification
        self.start_login_keystroke_collection(username)
        
        # Verify password first
        stored_salt = self.user_profiles[username]['password_salt']
        stored_key = self.user_profiles[username]['password_key']
        
        if not self._verify_password(stored_salt, stored_key, password):
            print("Incorrect password")
            self._log_security_event("failed_login", username, {"reason": "incorrect_password"})
            
            # Track failed attempts
            if username not in self.suspicious_attempts:
                self.suspicious_attempts[username] = {"count": 1, "first_attempt": time.time()}
            else:
                self.suspicious_attempts[username]["count"] += 1
            
            # Stop keystroke collection
            self.stop_login_keystroke_collection()
            return False
        
        # Stop keystroke collection and verify pattern
        self.stop_login_keystroke_collection()
        if not self.verify_keystroke_pattern(username):
            # Password correct but typing pattern incorrect - potential attack
            print("Password correct but typing pattern does not match stored profile")
            self._log_security_event("suspicious_login", username, {
                "reason": "keystroke_mismatch",
                "last_user": self.last_known_user
            })
            
            # If last user is different, this is very suspicious - require additional verification
            if self.last_known_user and self.last_known_user != username:
                self._handle_suspicious_login(username)
                return False
                
            # Otherwise, prompt for additional verification
            verification = messagebox.askquestion(
                "Additional Verification Required",
                "Your typing pattern is different than usual.\nIs this really you?",
                icon='warning'
            )
            
            if verification != 'yes':
                self._log_security_event("failed_verification", username)
                return False
        
        print("Password and behavioral pattern verified, starting monitoring...")
        
        self.current_user = username
        self.last_known_user = username
        self.keystroke_model = self.user_profiles[username]['keystroke_model']
        
        # Clear existing data
        self.keystroke_data = []
        self.keystroke_combinations = []
        
        # Reset suspicious attempts
        if username in self.suspicious_attempts:
            del self.suspicious_attempts[username]
        
        # Start monitoring in a separate thread
        self.is_monitoring = True
        self.auth_thread = threading.Thread(target=self._authentication_thread)
        self.auth_thread.daemon = True
        self.auth_thread.start()
        
        # Register hook
        keyboard.hook(self._on_key_event)
        
        self._log_security_event("successful_login", username)
        print(f"Started monitoring for user {username}")
        
        # If screen was protected, restore it
        if self.screen_protected:
            self._restore_screen()
            
        return True
    
    def _handle_suspicious_login(self, username):
        """Handle suspicious login attempts"""
        # Lock the account temporarily
        self.system_locked = True
        
        # Log the suspicious activity
        self._log_security_event("account_locked", username, {
            "reason": "suspicious_activity",
            "previous_user": self.last_known_user
        })
        
        # Show warning
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Security Alert",
            f"Suspicious login detected!\nThe account '{username}' has been locked for security reasons.\n"
            "Please contact your administrator."
        )
        root.destroy()
        
        # In a real system, this would send notifications to admins, etc.
    
    def stop_monitoring(self):
        """Stop continuous authentication monitoring"""
        if not self.is_monitoring:
            return True
            
        self.is_monitoring = False
        keyboard.unhook_all()
        if self.auth_thread:
            self.auth_thread.join(timeout=1.0)
            
        if self.current_user:
            self._log_security_event("logout", self.current_user)
            
        # Restore screen if it was protected
        if self.screen_protected:
            self._restore_screen()
            
        print("Monitoring stopped")
        return True
    
    def _on_key_event(self, event):
        """Handle keyboard events with enhanced features"""
        if event.event_type == keyboard.KEY_DOWN:
            current_time = time.time()
            current_key = event.name
            
            # If screen is protected and user types a key, perform quick verification
            if self.screen_protected and current_key not in ['ctrl', 'alt', 'shift']:
                # Check if the current typing pattern belongs to the authorized user
                # This allows the original user to start typing and restore the screen
                self._quick_user_verification()
            
            # Basic keystroke timing
            if self.last_key_time is not None:
                # Calculate time between keystrokes
                time_diff = current_time - self.last_key_time
                
                # Only record reasonable timing differences (0.01s to 2.5s)
                if 0.01 <= time_diff <= 2.5:
                    # Store both timing and key transition (which keys were pressed in sequence)
                    feature = [time_diff]
                    
                    # Add key transition information (convert to numerical features)
                    # Simple hash of the key transition to create a numerical feature
                    key_transition_hash = hash(f"{self.last_key}_{current_key}") % 1000
                    feature.append(key_transition_hash / 1000)  # Normalize to 0-1 range
                    
                    self.keystroke_data.append(feature)
            
            self.last_key_time = current_time
            self.last_key = current_key
    
    def _train_model(self):
        """Train anomaly detection model on collected keystroke data"""
        # Prepare keystroke data for training
        if len(self.keystroke_data) > 10:
            X_keystroke = np.array(self.keystroke_data)
            self.keystroke_model.fit(X_keystroke)
            print(f"Model trained on {len(self.keystroke_data)} keystroke samples")
        else:
            print("Warning: Not enough keystroke data collected for training")
    
    def _authentication_thread(self):
        """Background thread for continuous authentication checks"""
        while self.is_monitoring:
            # Determine check interval based on current state
            check_interval = self.quick_check_interval if self.screen_protected else self.auth_check_interval
            time.sleep(check_interval)
            
            # Skip checks if not enough data collected
            if len(self.keystroke_data) < self.min_keystrokes_for_check:
                continue
            
            # Check keystroke patterns
            X_keystroke = np.array(self.keystroke_data[-30:])
            keystroke_scores = self.keystroke_model.decision_function(X_keystroke)
            keystroke_avg_score = np.mean(keystroke_scores)
            
            print(f"Auth check - Keystroke score: {keystroke_avg_score:.2f}")
            
            # Determine if authentication fails
            if keystroke_avg_score < self.anomaly_threshold:
                self.consecutive_anomalies += 1
                print(f"Anomalous behavior detected ({self.consecutive_anomalies}/{self.consecutive_anomalies_for_protection})")
                
                # If consecutive anomalies reach threshold, activate privacy protection
                if self.consecutive_anomalies >= self.consecutive_anomalies_for_protection:
                    if not self.screen_protected:
                        self._protect_screen()
                    self.consecutive_anomalies = 0  # Reset counter
                
                # Also trigger standard verification if multiple anomalies are detected
                if self.consecutive_anomalies >= 2:
                    self.verification_required = True
                    self._request_verification()
            else:
                # If behavior is normal and screen is protected, consider restoring
                if self.screen_protected and self.consecutive_anomalies == 0:
                    # Check multiple samples to ensure it's the right user before restoring
                    self._quick_user_verification()
                
                self.consecutive_anomalies = 0  # Reset counter if normal behavior detected
    
    def _quick_user_verification(self):
        """Quickly verify if current user matches the profile to restore screen access"""
        # Only proceed if we have enough data
        if len(self.keystroke_data) < 5:
            return
            
        # Check last few keystrokes against model
        X_recent = np.array(self.keystroke_data[-min(len(self.keystroke_data), 10):])
        try:
            recent_scores = self.keystroke_model.decision_function(X_recent)
            recent_avg_score = np.mean(recent_scores)
            
            # If good match to user profile, restore screen
            if recent_avg_score >= self.anomaly_threshold and self.screen_protected:
                print("Original user detected, restoring screen access...")
                self._restore_screen()
        except Exception as e:
            print(f"Error during quick user verification: {e}")
    
    def _protect_screen(self):
        """Turn off or blank the screen to protect user privacy"""
        if self.screen_protected:
            return  # Already protected
            
        print("PRIVACY PROTECTION ACTIVATED: Unauthorized user detected!")
        self._log_security_event("privacy_protection_activated", self.current_user, {
            "reason": "unauthorized_user_detected"
        })
        
        # Mark screen as protected
        self.screen_protected = True
        
        # Determine the operating system
        os_name = platform.system()
        
        try:
            # Windows implementation
            if os_name == "Windows":
                # Turn off display
                ctypes.windll.user32.SendMessageW(0xFFFF, 0x0112, 0xF170, 2)
                
                # Lock workstation if higher protection level
                if self.privacy_protection_level >= 2:
                    ctypes.windll.user32.LockWorkStation()
            
            # macOS implementation
            elif os_name == "Darwin":
                # Use AppleScript to put display to sleep
                subprocess.call(["osascript", "-e", 'tell application "System Events" to sleep'])
                
                # Lock screen if higher protection level
                if self.privacy_protection_level >= 2:
                    subprocess.call(["osascript", "-e", 'tell application "System Events" to keystroke "q" using {command down, control down}'])
            
            # Linux implementation
            elif os_name == "Linux":
                # Try different methods for screen blanking
                try:
                    # Try xset to turn off screen
                    subprocess.call(["xset", "dpms", "force", "off"])
                except:
                    try:
                        # Try using GNOME's dbus interface
                        subprocess.call(["dbus-send", "--session", "--dest=org.gnome.ScreenSaver", 
                                        "--type=method_call", "/org/gnome/ScreenSaver", 
                                        "org.gnome.ScreenSaver.SetActive", "boolean:true"])
                    except:
                        print("Could not turn off screen - GNOME screensaver not available")
                
                # Lock screen if higher protection level
                if self.privacy_protection_level >= 2:
                    try:
                        subprocess.call(["gnome-screensaver-command", "-l"])
                    except:
                        try:
                            subprocess.call(["loginctl", "lock-session"])
                        except:
                            print("Could not lock screen")
            
            # Show security notification if highest protection level
            if self.privacy_protection_level >= 3:
                def show_alert():
                    root = tk.Tk()
                    root.attributes("-topmost", True)
                    root.withdraw()
                    messagebox.showwarning(
                        "Security Alert",
                        "Unauthorized user detected!\nScreen has been blanked for privacy protection."
                    )
                    root.destroy()
                
                threading.Thread(target=show_alert).start()
                
            print("Screen turned off for privacy protection")
            
        except Exception as e:
            print(f"Error protecting screen: {e}")
    
    def _restore_screen(self):
        """Restore the screen after privacy protection"""
        if not self.screen_protected:
            return  # Not protected
            
        print("Restoring screen access...")
        self._log_security_event("privacy_protection_deactivated", self.current_user, {
            "reason": "authorized_user_returned"
        })
        
        # Determine the operating system
        os_name = platform.system()
        
        try:
            # Windows implementation
            if os_name == "Windows":
                # Send key press to wake screen
                keyboard.press_and_release('shift')
            
            # macOS implementation
            elif os_name == "Darwin":
                # Send key press to wake screen
                keyboard.press_and_release('shift')
            
            # Linux implementation
            elif os_name == "Linux":
                # Try to turn the screen back on
                try:
                    subprocess.call(["xset", "dpms", "force", "on"])
                except:
                    print("Could not turn screen back on")
            
            # Mark screen as no longer protected
            self.screen_protected = False
            print("Screen access restored")
            
        except Exception as e:
            print(f"Error restoring screen: {e}")
    
    def _request_verification(self):
        """Display verification prompt to user"""
        # Don't show verification prompt if screen is protected
        if self.screen_protected:
            return
            
        def show_dialog():
            root = tk.Tk()
            root.withdraw()  # Hide the main window
            
            # Ask for password verification
            password = simpledialog.askstring(
                "Verification Required", 
                f"Unusual typing pattern detected for user {self.current_user}.\nPlease enter your password to verify identity:",
                show='*'
            )
            
            if password:
                # Verify password
                stored_salt = self.user_profiles[self.current_user]['password_salt']
                stored_key = self.user_profiles[self.current_user]['password_key']
                
                if self._verify_password(stored_salt, stored_key, password):
                    # User confirmed identity, update model slightly to adapt
                    messagebox.showinfo("Verification Successful", "Identity verified. Adapting to your current typing patterns.")
                    self._log_security_event("successful_verification", self.current_user)
                    self._adapt_model()
                    self.verification_required = False
                else:
                    # User failed verification, lock system
                    self.stop_monitoring()
                    self._log_security_event("failed_verification", self.current_user)
                    messagebox.showwarning(
                        "Authentication Failed",
                        "Incorrect password. System locked due to failed authentication.\nPlease contact administrator."
                    )
            else:
                # User cancelled verification, lock system
                self.stop_monitoring()
                self._log_security_event("cancelled_verification", self.current_user)
                messagebox.showwarning(
                    "Authentication Cancelled",
                    "Verification cancelled. System locked for security reasons.\nPlease contact administrator."
                )
            
            root.destroy()
        
        # Show dialog in separate thread to avoid blocking
        threading.Thread(target=show_dialog).start()
    
    def _adapt_model(self):
        """Slightly adapt model to account for minor behavioral changes"""
        print("Adapting model to recent typing behavior")
        
        # Only keep the most recent data for adaptation
        recent_data = self.keystroke_data[-min(len(self.keystroke_data), 100):]
        
        # Blend with existing data
        if hasattr(self.keystroke_model, 'base_estimator_'):
            # This is a simplified adaptation - in a real system, more sophisticated
            # methods would be used to incrementally update the model
            X_recent = np.array(recent_data)
            self.keystroke_model.fit(X_recent)
            
            # Update stored profile
            if self.current_user:
                self.user_profiles[self.current_user]['keystroke_model'] = self.keystroke_model
                
                # Save profiles to disk
                with open('user_profiles.pkl', 'wb') as f:
                    pickle.dump(self.user_profiles, f)
                    
            print(f"Model adapted with {len(recent_data)} recent keystroke samples")
    
    def set_privacy_protection_level(self, level):
        """Set the privacy protection level
        1 = screen off only
        2 = screen off + lock
        3 = screen off + lock + alert
        """
        if 1 <= level <= 3:
            self.privacy_protection_level = level
            print(f"Privacy protection level set to {level}")
            return True
        return False

# Usage example
if __name__ == "__main__":
    # Create authentication system
    auth_system = KeystrokeBehavioralAuthSystem()
    
    # For demonstration purposes, simple text-based interface
    while True:
        print("\nKeystroke Behavioral Authentication System with Privacy Protection")
        print("1. Enroll new user")
        print("2. Log in and start monitoring")
        print("3. View security log")
        print("4. Privacy protection settings")
        print("5. Exit")
        
        if auth_system.system_locked:
            print("\nWARNING: System is currently locked due to suspicious activity!")
            print("Please contact your administrator to unlock.")
            choice = input("Enter 5 to exit: ")
            if choice == '5':
                break
            continue
        
        choice = input("Select option: ")
        
        if choice == '1':
            username = input("Enter username to enroll: ")
            password = input("Enter password: ")
            print("Please type naturally for 60 seconds to collect behavioral data...")
            auth_system.start_enrollment(username, password, duration=60)
        
        elif choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            
            if username in auth_system.user_profiles:
                success = auth_system.start_monitoring(username, password)
                if success:
                    print(f"Successfully logged in as {username}")
                    print("Continuous monitoring active - type normally")
                    print("If another person types, the screen will automatically be turned off")
                    print("Press Ctrl+C to log out")
                    
                    # Keep application running
                    try:
                        while auth_system.is_monitoring:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        auth_system.stop_monitoring()
                        print("Logged out")
                else:
                    print("Login failed")
            else:
                print(f"User {username} not found. Please enroll first.")
        
        elif choice == '3':
            if len(auth_system.security_log) == 0:
                print("No security events logged yet.")
            else:
                print("\nRecent Security Events:")
                for i, event in enumerate(auth_system.security_log[-10:]):
                    print(f"{i+1}. [{event['timestamp']}] {event['event_type']} - User: {event['username']}")
                print(f"Total events: {len(auth_system.security_log)}")
        
        elif choice == '4':
            print("\nPrivacy Protection Settings")
            print("1. Basic (Screen off only)")
            print("2. Medium (Screen off + lock workstation)")
            print("3. High (Screen off + lock + alert)")
            print("4. Set anomaly sensitivity")
            print("5. Back to main menu")
            
            setting_choice = input("Select option: ")
            
            if setting_choice in ['1', '2', '3']:
                level = int(setting_choice)
                auth_system.set_privacy_protection_level(level)
                print(f"Privacy protection level set to {level}")
            
            elif setting_choice == '4':
                try:
                    sensitivity = int(input("Enter anomaly sensitivity (1-5, lower is more sensitive): "))
                    if 1 <= sensitivity <= 5:
                        auth_system.consecutive_anomalies_for_protection = sensitivity
                        print(f"Anomaly sensitivity set to {sensitivity}")
                    else:
                        print("Invalid sensitivity level. Please enter a number between 1 and 5.")
                except ValueError:
                    print("Invalid input. Please enter a number.")
        
        elif choice == '5':
            print("Exiting...")
            break
        
        else:
            print("Invalid option. Please try again.")