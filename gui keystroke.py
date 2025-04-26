import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import keyboard
import time
import threading
import json
import datetime
from keystroke import KeystrokeBehavioralAuthSystem  # Import the existing system

class KeystrokeAuthGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Keystroke Behavioral Authentication System")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Create the authentication system
        self.auth_system = KeystrokeBehavioralAuthSystem()
        
        # Create main frame
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.login_tab = ttk.Frame(self.notebook)
        self.enrollment_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        self.security_log_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.login_tab, text="Login")
        self.notebook.add(self.enrollment_tab, text="User Enrollment")
        self.notebook.add(self.settings_tab, text="Settings")
        self.notebook.add(self.security_log_tab, text="Security Log")
        
        # Create status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Setup each tab
        self._setup_login_tab()
        self._setup_enrollment_tab()
        self._setup_settings_tab()
        self._setup_security_log_tab()
        
        # Initialize the monitoring status
        self.is_logged_in = False
        
        # Intercept window close event
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        
        # Refresh security log every 30 seconds
        self._schedule_log_refresh()

    def _setup_login_tab(self):
        """Setup the login tab contents"""
        frame = ttk.Frame(self.login_tab, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(frame, text="User Login", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Login form
        form_frame = ttk.Frame(frame)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.username_var, width=30).grid(row=0, column=1, pady=5, padx=5)
        
        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.password_var, show="*", width=30).grid(row=1, column=1, pady=5, padx=5)
        
        # Login button
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        self.login_btn = ttk.Button(btn_frame, text="Login", command=self._handle_login, width=20)
        self.login_btn.pack(side=tk.LEFT, padx=5)
        
        self.logout_btn = ttk.Button(btn_frame, text="Logout", command=self._handle_logout, width=20, state=tk.DISABLED)
        self.logout_btn.pack(side=tk.LEFT, padx=5)
        
        # Status information
        self.login_status_var = tk.StringVar()
        self.login_status_var.set("Not logged in")
        self.login_status_label = ttk.Label(frame, textvariable=self.login_status_var, font=("Arial", 10), foreground="grey")
        self.login_status_label.pack(pady=10)
        
        # User instructions
        instructions = ttk.LabelFrame(frame, text="Instructions")
        instructions.pack(fill=tk.X, pady=10)
        
        instruction_text = ("1. Enter your username and password\n"
                           "2. Click Login to begin monitoring\n"
                           "3. The system will continuously verify your typing pattern\n"
                           "4. If an unauthorized user is detected, the screen will be protected\n"
                           "5. Click Logout when finished")
        
        ttk.Label(instructions, text=instruction_text, justify=tk.LEFT).pack(padx=10, pady=10)

    def _setup_enrollment_tab(self):
        """Setup the enrollment tab contents"""
        frame = ttk.Frame(self.enrollment_tab, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(frame, text="New User Enrollment", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Enrollment form
        form_frame = ttk.Frame(frame)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(form_frame, text="New Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.new_username_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.new_username_var, width=30).grid(row=0, column=1, pady=5, padx=5)
        
        ttk.Label(form_frame, text="New Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.new_password_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.new_password_var, show="*", width=30).grid(row=1, column=1, pady=5, padx=5)
        
        ttk.Label(form_frame, text="Confirm Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.confirm_password_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.confirm_password_var, show="*", width=30).grid(row=2, column=1, pady=5, padx=5)
        
        ttk.Label(form_frame, text="Enrollment Duration:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.duration_var = tk.IntVar(value=60)
        duration_frame = ttk.Frame(form_frame)
        duration_frame.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        ttk.Radiobutton(duration_frame, text="30 seconds", variable=self.duration_var, value=30).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(duration_frame, text="60 seconds", variable=self.duration_var, value=60).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(duration_frame, text="120 seconds", variable=self.duration_var, value=120).pack(side=tk.LEFT, padx=5)
        
        # Enrollment button
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        self.enroll_btn = ttk.Button(btn_frame, text="Start Enrollment", command=self._handle_enrollment, width=20)
        self.enroll_btn.pack()
        
        # Enrollment status
        self.enrollment_status_var = tk.StringVar()
        self.enrollment_status_var.set("Ready to enroll")
        self.enrollment_status_label = ttk.Label(frame, textvariable=self.enrollment_status_var, font=("Arial", 10), foreground="grey")
        self.enrollment_status_label.pack(pady=10)
        
        # Progress bar for enrollment
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, length=300, mode='determinate', variable=self.progress_var)
        self.progress.pack(pady=10)
        
        # User instructions
        instructions = ttk.LabelFrame(frame, text="Instructions")
        instructions.pack(fill=tk.X, pady=10)
        
        instruction_text = ("1. Enter a new username and password\n"
                           "2. Select enrollment duration\n"
                           "3. Click 'Start Enrollment' and type naturally during the enrollment period\n"
                           "4. The system will learn your unique typing pattern\n"
                           "5. More typing leads to better recognition accuracy")
        
        ttk.Label(instructions, text=instruction_text, justify=tk.LEFT).pack(padx=10, pady=10)

    def _setup_settings_tab(self):
        """Setup the settings tab contents"""
        frame = ttk.Frame(self.settings_tab, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(frame, text="System Settings", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Settings form
        settings_frame = ttk.LabelFrame(frame, text="Privacy Protection Settings")
        settings_frame.pack(fill=tk.X, pady=10)
        
        # Protection level
        ttk.Label(settings_frame, text="Protection Level:").grid(row=0, column=0, sticky=tk.W, pady=10, padx=10)
        self.protection_level_var = tk.IntVar(value=self.auth_system.privacy_protection_level)
        
        level_frame = ttk.Frame(settings_frame)
        level_frame.grid(row=0, column=1, sticky=tk.W, pady=10)
        
        ttk.Radiobutton(level_frame, text="Basic (Screen off only)", 
                       variable=self.protection_level_var, value=1).pack(anchor=tk.W)
        ttk.Radiobutton(level_frame, text="Medium (Screen off + lock workstation)", 
                       variable=self.protection_level_var, value=2).pack(anchor=tk.W)
        ttk.Radiobutton(level_frame, text="High (Screen off + lock + alert)", 
                       variable=self.protection_level_var, value=3).pack(anchor=tk.W)
        
        # Sensitivity settings
        sensitivity_frame = ttk.LabelFrame(frame, text="Detection Sensitivity")
        sensitivity_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(sensitivity_frame, text="Anomaly Threshold:").grid(row=0, column=0, sticky=tk.W, pady=10, padx=10)
        self.anomaly_threshold_var = tk.DoubleVar(value=abs(self.auth_system.anomaly_threshold * 10))
        
        anomaly_scale = ttk.Scale(sensitivity_frame, from_=1, to=10, orient=tk.HORIZONTAL,
                                 variable=self.anomaly_threshold_var, length=200)
        anomaly_scale.grid(row=0, column=1, padx=10, pady=10)
        
        threshold_label_frame = ttk.Frame(sensitivity_frame)
        threshold_label_frame.grid(row=0, column=2, padx=10)
        ttk.Label(threshold_label_frame, text="Less Sensitive").pack(side=tk.TOP)
        ttk.Label(threshold_label_frame, text="More Sensitive").pack(side=tk.BOTTOM)
        
        ttk.Label(sensitivity_frame, text="Consecutive Anomalies Before Protection:").grid(row=1, column=0, sticky=tk.W, pady=10, padx=10)
        self.consecutive_anomalies_var = tk.IntVar(value=self.auth_system.consecutive_anomalies_for_protection)
        
        anomaly_count_scale = ttk.Scale(sensitivity_frame, from_=1, to=5, orient=tk.HORIZONTAL,
                                       variable=self.consecutive_anomalies_var, length=200)
        anomaly_count_scale.grid(row=1, column=1, padx=10, pady=10)
        
        count_label_frame = ttk.Frame(sensitivity_frame)
        count_label_frame.grid(row=1, column=2, padx=10)
        ttk.Label(count_label_frame, text="More Sensitive (1)").pack(side=tk.TOP)
        ttk.Label(count_label_frame, text="Less Sensitive (5)").pack(side=tk.BOTTOM)
        
        # Timing settings
        timing_frame = ttk.LabelFrame(frame, text="Check Intervals")
        timing_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(timing_frame, text="Authentication Check Interval (seconds):").grid(row=0, column=0, sticky=tk.W, pady=10, padx=10)
        self.auth_interval_var = tk.IntVar(value=self.auth_system.auth_check_interval)
        
        ttk.Spinbox(timing_frame, from_=1, to=30, textvariable=self.auth_interval_var, width=5).grid(row=0, column=1, padx=10, pady=10)
        
        ttk.Label(timing_frame, text="Quick Check Interval (seconds):").grid(row=1, column=0, sticky=tk.W, pady=10, padx=10)
        self.quick_interval_var = tk.IntVar(value=self.auth_system.quick_check_interval)
        
        ttk.Spinbox(timing_frame, from_=1, to=10, textvariable=self.quick_interval_var, width=5).grid(row=1, column=1, padx=10, pady=10)
        
        # Save settings button
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        save_btn = ttk.Button(btn_frame, text="Save Settings", command=self._save_settings, width=20)
        save_btn.pack()

    def _setup_security_log_tab(self):
        """Setup the security log tab contents"""
        frame = ttk.Frame(self.security_log_tab, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(frame, text="Security Log", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Log display
        log_frame = ttk.Frame(frame)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, width=80, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)  # Make it read-only
        
        # Refresh button
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        
        refresh_btn = ttk.Button(btn_frame, text="Refresh Log", command=self._refresh_security_log, width=20)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = ttk.Button(btn_frame, text="Clear Display", command=self._clear_log_display, width=20)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Initial log display
        self._refresh_security_log()

    def _handle_login(self):
        """Handle login button click"""
        username = self.username_var.get().strip()
        password = self.password_var.get()
        
        if not username or not password:
            messagebox.showerror("Login Error", "Please enter both username and password")
            return
        
        self.status_var.set("Logging in...")
        
        # Enable login keystroke collection
        self.auth_system.start_login_keystroke_collection(username)
        
        # Perform login with slight delay to collect keystroke data
        def delayed_login():
            time.sleep(0.5)  # Give time to collect some keystrokes
            
            # Stop keystroke collection
            self.auth_system.stop_login_keystroke_collection()
            
            # Try to login
            success = self.auth_system.start_monitoring(username, password)
            
            if success:
                self.login_status_var.set(f"Logged in as {username}")
                self.login_status_label.config(foreground="green")
                self.status_var.set(f"Monitoring active for {username}")
                self.is_logged_in = True
                
                # Update UI state
                self.login_btn.config(state=tk.DISABLED)
                self.logout_btn.config(state=tk.NORMAL)
                self.enroll_btn.config(state=tk.DISABLED)
                self.notebook.tab(1, state="disabled")  # Disable enrollment tab
            else:
                self.login_status_var.set("Login failed")
                self.login_status_label.config(foreground="red")
                self.status_var.set("Ready")
                messagebox.showerror("Login Failed", "Invalid username, password, or typing pattern")
        
        # Run login in separate thread to avoid UI freeze
        threading.Thread(target=delayed_login).start()

    def _handle_logout(self):
        """Handle logout button click"""
        if self.is_logged_in:
            self.auth_system.stop_monitoring()
            self.is_logged_in = False
            
            # Update UI state
            self.login_status_var.set("Not logged in")
            self.login_status_label.config(foreground="grey")
            self.status_var.set("Ready")
            self.login_btn.config(state=tk.NORMAL)
            self.logout_btn.config(state=tk.DISABLED)
            self.enroll_btn.config(state=tk.NORMAL)
            self.notebook.tab(1, state="normal")  # Enable enrollment tab
            
            # Clear password field
            self.password_var.set("")

    def _handle_enrollment(self):
        """Handle enrollment button click"""
        username = self.new_username_var.get().strip()
        password = self.new_password_var.get()
        confirm = self.confirm_password_var.get()
        duration = self.duration_var.get()
        
        if not username or not password:
            messagebox.showerror("Enrollment Error", "Please enter both username and password")
            return
            
        if password != confirm:
            messagebox.showerror("Enrollment Error", "Passwords do not match")
            return
            
        if username in self.auth_system.user_profiles:
            overwrite = messagebox.askyesno("User Exists", 
                                           f"User {username} already exists. Overwrite profile?")
            if not overwrite:
                return
        
        # Disable buttons during enrollment
        self.enroll_btn.config(state=tk.DISABLED)
        self.login_btn.config(state=tk.DISABLED)
        
        # Update status
        self.enrollment_status_var.set(f"Enrolling user {username}...")
        self.status_var.set(f"Collecting keystrokes for {username}...")
        
        # Start enrollment in a separate thread
        self.progress_var.set(0)
        
        def enrollment_thread():
            start_time = time.time()
            
            # Show instructions in a messagebox
            root = tk.Toplevel(self.root)
            root.title("Enrollment Instructions")
            root.geometry("400x300")
            root.resizable(False, False)
            root.transient(self.root)
            root.grab_set()
            
            instruction_label = ttk.Label(root, text="Please type naturally to create your behavioral profile", 
                                         font=("Arial", 12))
            instruction_label.pack(pady=20)
            
            text_area = scrolledtext.ScrolledText(root, width=40, height=10)
            text_area.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
            text_area.insert(tk.END, "Type anything here to create your profile...\n\n")
            text_area.focus_set()
            
            time_label = ttk.Label(root, text=f"Time remaining: {duration} seconds")
            time_label.pack(pady=10)
            
            # Start enrollment
            self.auth_system.current_user = username
            self.auth_system.keystroke_data = []
            keyboard.hook(self.auth_system._on_key_event)
            
            # Update progress and countdown
            while time.time() - start_time < duration:
                remaining = int(duration - (time.time() - start_time))
                progress = ((time.time() - start_time) / duration) * 100
                
                # Update UI elements in the main thread
                self.root.after(10, lambda r=remaining, p=progress: self._update_enrollment_progress(r, p))
                
                # Update the time label in the text entry window
                time_label.config(text=f"Time remaining: {remaining} seconds")
                root.update()
                
                time.sleep(0.1)
            
            # Finish enrollment
            keyboard.unhook_all()
            
            # Close the typing window
            root.destroy()
            
            # Save the profile
            if len(self.auth_system.keystroke_data) >= 20:
                # Store username and hashed password
                salt, key = self.auth_system._hash_password(password)
                
                # Train model on collected data
                self.auth_system._train_model()
                
                # Save user profile
                self.auth_system.user_profiles[username] = {
                    'keystroke_model': self.auth_system.keystroke_model,
                    'timestamp': time.time(),
                    'password_salt': salt,
                    'password_key': key,
                    'sample_size': len(self.auth_system.keystroke_data),
                    'enrollment_data': self.auth_system.keystroke_data[:100]
                }
                
                # Save profiles to disk
                with open('user_profiles.pkl', 'wb') as f:
                    import pickle
                    pickle.dump(self.auth_system.user_profiles, f)
                
                # Log enrollment
                self.auth_system._log_security_event("enrollment", username, {
                    "samples": len(self.auth_system.keystroke_data),
                    "time": datetime.datetime.now().isoformat()
                })
                
                # Update UI elements in the main thread
                self.root.after(0, lambda: self._enrollment_complete(True, username, len(self.auth_system.keystroke_data)))
            else:
                # Not enough data
                self.root.after(0, lambda: self._enrollment_complete(False, username, len(self.auth_system.keystroke_data)))
        
        # Start enrollment thread
        threading.Thread(target=enrollment_thread).start()

    def _update_enrollment_progress(self, remaining, progress):
        """Update enrollment progress display"""
        self.progress_var.set(progress)
        self.enrollment_status_var.set(f"Enrolling... {remaining} seconds remaining")

    def _enrollment_complete(self, success, username, samples):
        """Handle enrollment completion"""
        # Re-enable buttons
        self.enroll_btn.config(state=tk.NORMAL)
        self.login_btn.config(state=tk.NORMAL)
        
        if success:
            self.enrollment_status_var.set(f"Enrollment complete for {username} with {samples} samples")
            self.status_var.set("Ready")
            messagebox.showinfo("Enrollment Complete", 
                               f"Successfully enrolled {username} with {samples} keystroke samples")
            
            # Clear form fields
            self.new_username_var.set("")
            self.new_password_var.set("")
            self.confirm_password_var.set("")
            
            # Switch to login tab
            self.notebook.select(0)
            self.username_var.set(username)
        else:
            self.enrollment_status_var.set("Enrollment failed - not enough data")
            self.status_var.set("Ready")
            messagebox.showerror("Enrollment Failed", 
                                f"Not enough keystroke data collected ({samples} samples). Please try again.")

    def _save_settings(self):
        """Save system settings"""
        # Update protection level
        protection_level = self.protection_level_var.get()
        self.auth_system.set_privacy_protection_level(protection_level)
        
        # Update anomaly threshold
        anomaly_threshold = -self.anomaly_threshold_var.get() / 10  # Convert from 1-10 scale to negative values
        self.auth_system.anomaly_threshold = anomaly_threshold
        self.auth_system.login_anomaly_threshold = anomaly_threshold - 0.1  # Slightly stricter for login
        
        # Update consecutive anomalies setting
        consecutive_anomalies = self.consecutive_anomalies_var.get()
        self.auth_system.consecutive_anomalies_for_protection = consecutive_anomalies
        
        # Update timing intervals
        self.auth_system.auth_check_interval = self.auth_interval_var.get()
        self.auth_system.quick_check_interval = self.quick_interval_var.get()
        
        # Confirm settings saved
        self.status_var.set("Settings saved")
        messagebox.showinfo("Settings", "Settings have been updated")

    def _refresh_security_log(self):
        """Refresh the security log display"""
        # Enable editing
        self.log_text.config(state=tk.NORMAL)
        
        # Clear current log
        self.log_text.delete(1.0, tk.END)
        
        # Display log entries
        if len(self.auth_system.security_log) == 0:
            self.log_text.insert(tk.END, "No security events logged yet.")
        else:
            self.log_text.insert(tk.END, "Recent Security Events:\n")
            self.log_text.insert(tk.END, "-" * 80 + "\n")
            
            # Show the most recent events first
            for event in reversed(self.auth_system.security_log[-50:]):
                timestamp = event['timestamp']
                event_type = event['event_type']
                username = event['username']
                
                entry = f"[{timestamp}] {event_type.upper()} - User: {username}\n"
                
                # Add details if available
                if 'details' in event and event['details']:
                    details = event['details']
                    for key, value in details.items():
                        entry += f"    {key}: {value}\n"
                
                entry += "-" * 80 + "\n"
                self.log_text.insert(tk.END, entry)
        
        # Disable editing
        self.log_text.config(state=tk.DISABLED)

    def _clear_log_display(self):
        """Clear the log display"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _schedule_log_refresh(self):
        """Schedule periodic log refresh"""
        self._refresh_security_log()
        self.root.after(30000, self._schedule_log_refresh)  # Refresh every 30 seconds

    def _on_close(self):
        """Handle window close event"""
        if self.is_logged_in:
            # Ask user to confirm logout
            confirm = messagebox.askyesno("Confirm Exit", 
                                         "You are still logged in and being monitored.\nDo you want to exit?")
            if confirm:
                self.auth_system.stop_monitoring()
                self.root.destroy()
        else:
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = KeystrokeAuthGUI(root)
    root.mainloop()