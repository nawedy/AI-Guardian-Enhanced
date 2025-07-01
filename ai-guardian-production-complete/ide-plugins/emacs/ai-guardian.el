;;; ai-guardian.el --- AI Guardian security scanning for Emacs -*- lexical-binding: t; -*-

;; Copyright (C) 2024 OmniPanel AI

;; Author: OmniPanel AI Team
;; Version: 3.0.0
;; Package-Requires: ((emacs "25.1") (request "0.3.0") (websocket "1.12"))
;; Keywords: security, vulnerability, scanning, ai
;; URL: https://github.com/omnipanel/ai-guardian

;;; Commentary:

;; AI Guardian provides real-time security scanning and vulnerability detection
;; for your code directly within Emacs. It integrates with the AI Guardian
;; backend services to provide comprehensive security analysis.

;; Features:
;; - Real-time vulnerability scanning
;; - Support for 10+ programming languages
;; - Compliance monitoring (GDPR, HIPAA, PCI-DSS, etc.)
;; - Automated remediation suggestions
;; - Project-wide security analysis
;; - Integration with flycheck for inline warnings

;;; Code:

(require 'request)
(require 'websocket)
(require 'json)
(require 'flycheck nil t)

;;; Customization

(defgroup ai-guardian nil
  "AI Guardian security scanning integration."
  :group 'tools
  :prefix "ai-guardian-")

(defcustom ai-guardian-api-url "http://localhost:5002"
  "Base URL for AI Guardian API."
  :type 'string
  :group 'ai-guardian)

(defcustom ai-guardian-websocket-url "ws://localhost:8765"
  "WebSocket URL for real-time monitoring."
  :type 'string
  :group 'ai-guardian)

(defcustom ai-guardian-auto-scan t
  "Enable automatic scanning on file changes."
  :type 'boolean
  :group 'ai-guardian)

(defcustom ai-guardian-scan-on-save t
  "Enable scanning when files are saved."
  :type 'boolean
  :group 'ai-guardian)

(defcustom ai-guardian-show-inline-warnings t
  "Show inline warnings for vulnerabilities."
  :type 'boolean
  :group 'ai-guardian)

(defcustom ai-guardian-highlight-vulnerabilities t
  "Highlight vulnerable code lines."
  :type 'boolean
  :group 'ai-guardian)

(defcustom ai-guardian-scan-delay 2
  "Delay in seconds before auto-scanning after changes."
  :type 'integer
  :group 'ai-guardian)

;;; Variables

(defvar ai-guardian-vulnerabilities (make-hash-table :test 'equal)
  "Hash table storing vulnerabilities for each file.")

(defvar ai-guardian-websocket nil
  "WebSocket connection for real-time monitoring.")

(defvar ai-guardian-scan-timer nil
  "Timer for delayed scanning.")

(defvar ai-guardian-mode-line-format " [🛡️%s]"
  "Format string for mode line display.")

;;; Faces

(defface ai-guardian-critical-face
  '((t (:background "#5f0000" :foreground "white")))
  "Face for critical vulnerabilities."
  :group 'ai-guardian)

(defface ai-guardian-high-face
  '((t (:background "#5f5f00" :foreground "white")))
  "Face for high severity vulnerabilities."
  :group 'ai-guardian)

(defface ai-guardian-medium-face
  '((t (:background "#005f00" :foreground "white")))
  "Face for medium severity vulnerabilities."
  :group 'ai-guardian)

(defface ai-guardian-low-face
  '((t (:background "#00005f" :foreground "white")))
  "Face for low severity vulnerabilities."
  :group 'ai-guardian)

;;; Utility Functions

(defun ai-guardian--get-language-from-filename (filename)
  "Determine programming language from FILENAME."
  (let ((ext (file-name-extension filename)))
    (cond
     ((string= ext "py") "python")
     ((string= ext "js") "javascript")
     ((string= ext "ts") "typescript")
     ((string= ext "java") "java")
     ((string= ext "cs") "csharp")
     ((string= ext "go") "go")
     ((string= ext "rs") "rust")
     ((string= ext "php") "php")
     ((string= ext "rb") "ruby")
     ((string= ext "swift") "swift")
     ((string= ext "kt") "kotlin")
     ((member ext '("cpp" "cxx" "cc")) "cpp")
     ((string= ext "c") "c")
     ((member ext '("h" "hpp" "hxx")) "c")
     (t "unknown"))))

(defun ai-guardian--get-severity-face (severity)
  "Get face for SEVERITY level."
  (cond
   ((string= severity "critical") 'ai-guardian-critical-face)
   ((string= severity "high") 'ai-guardian-high-face)
   ((string= severity "medium") 'ai-guardian-medium-face)
   ((string= severity "low") 'ai-guardian-low-face)
   (t 'default)))

(defun ai-guardian--message (format-string &rest args)
  "Display AI Guardian message with FORMAT-STRING and ARGS."
  (message (concat "AI Guardian: " format-string) args))

;;; Core Functions

(defun ai-guardian-scan-buffer ()
  "Scan current buffer for vulnerabilities."
  (interactive)
  (when (buffer-file-name)
    (let* ((filename (buffer-file-name))
           (content (buffer-string))
           (language (ai-guardian--get-language-from-filename filename)))
      
      (if (string= language "unknown")
          (ai-guardian--message "Unsupported file type")
        
        (ai-guardian--message "Scanning for vulnerabilities...")
        
        (request (concat ai-guardian-api-url "/api/scan")
          :type "POST"
          :headers '(("Content-Type" . "application/json"))
          :data (json-encode `((code . ,content)
                              (language . ,language)
                              (filename . ,(file-name-nondirectory filename))))
          :success (cl-function
                    (lambda (&key data &allow-other-keys)
                      (ai-guardian--process-scan-results data filename)))
          :error (cl-function
                  (lambda (&key error-thrown &allow-other-keys)
                    (ai-guardian--message "Scan failed: %s" error-thrown))))))))

(defun ai-guardian--process-scan-results (data filename)
  "Process scan results DATA for FILENAME."
  (let* ((result (json-read-from-string data))
           (vulnerabilities (cdr (assoc 'vulnerabilities result))))
    
    ;; Clear previous results
    (ai-guardian--clear-highlights filename)
    
    ;; Store vulnerabilities
    (puthash filename vulnerabilities ai-guardian-vulnerabilities)
    
    (if (= (length vulnerabilities) 0)
        (ai-guardian--message "No vulnerabilities found ✓")
      
      ;; Count by severity
      (let ((counts (make-hash-table :test 'equal)))
        (dolist (vuln vulnerabilities)
          (let ((severity (cdr (assoc 'severity vuln))))
            (puthash severity (1+ (gethash severity counts 0)) counts)))
        
        (ai-guardian--message "Found %d vulnerabilities - Critical: %d, High: %d, Medium: %d, Low: %d"
                             (length vulnerabilities)
                             (gethash "critical" counts 0)
                             (gethash "high" counts 0)
                             (gethash "medium" counts 0)
                             (gethash "low" counts 0))
        
        ;; Add highlights and overlays
        (when ai-guardian-highlight-vulnerabilities
          (ai-guardian--add-highlights vulnerabilities filename))
        
        ;; Update flycheck if available
        (when (and (featurep 'flycheck) flycheck-mode)
          (flycheck-buffer))))))

(defun ai-guardian--add-highlights (vulnerabilities filename)
  "Add highlights for VULNERABILITIES in FILENAME."
  (save-excursion
    (dolist (vuln vulnerabilities)
      (let* ((line (cdr (assoc 'line vuln)))
             (severity (cdr (assoc 'severity vuln)))
             (description (cdr (assoc 'description vuln)))
             (face (ai-guardian--get-severity-face severity)))
        
        (goto-char (point-min))
        (forward-line (1- line))
        (let ((overlay (make-overlay (line-beginning-position) (line-end-position))))
          (overlay-put overlay 'face face)
          (overlay-put overlay 'ai-guardian-vulnerability t)
          (overlay-put overlay 'help-echo description)
          (overlay-put overlay 'priority 100))))))

(defun ai-guardian--clear-highlights (filename)
  "Clear all AI Guardian highlights in current buffer."
  (remove-overlays (point-min) (point-max) 'ai-guardian-vulnerability t))

(defun ai-guardian-scan-project ()
  "Scan entire project for vulnerabilities."
  (interactive)
  (let* ((project-root (or (locate-dominating-file default-directory ".git")
                          default-directory))
         (files (ai-guardian--find-project-files project-root)))
    
    (if (not files)
        (ai-guardian--message "No supported files found in project")
      
      (ai-guardian--message "Scanning project (%d files)..." (length files))
      
      (let ((total-vulnerabilities 0)
            (files-with-issues 0)
            (scanned-files 0))
        
        (dolist (file files)
          (when (< scanned-files 50) ; Limit for performance
            (condition-case err
                (with-temp-buffer
                  (insert-file-contents file)
                  (let* ((content (buffer-string))
                         (language (ai-guardian--get-language-from-filename file)))
                    
                    (when (not (string= language "unknown"))
                      (request (concat ai-guardian-api-url "/api/scan")
                        :type "POST"
                        :headers '(("Content-Type" . "application/json"))
                        :data (json-encode `((code . ,content)
                                            (language . ,language)
                                            (filename . ,(file-name-nondirectory file))))
                        :sync t
                        :success (cl-function
                                  (lambda (&key data &allow-other-keys)
                                    (let* ((result (json-read-from-string data))
                                           (vulnerabilities (cdr (assoc 'vulnerabilities result))))
                                      (when (> (length vulnerabilities) 0)
                                        (setq total-vulnerabilities (+ total-vulnerabilities (length vulnerabilities)))
                                        (setq files-with-issues (1+ files-with-issues))))))
                        :error (lambda (&rest _) nil))
                      (setq scanned-files (1+ scanned-files)))))
              (error nil))))
        
        (ai-guardian--message "Project scan complete - %d vulnerabilities found in %d files"
                             total-vulnerabilities files-with-issues)))))

(defun ai-guardian--find-project-files (project-root)
  "Find all supported files in PROJECT-ROOT."
  (let ((extensions '("py" "js" "ts" "java" "cs" "go" "rs" "php" "rb" "swift" "kt" "cpp" "c" "h"))
        (files '()))
    (dolist (ext extensions)
      (setq files (append files
                         (directory-files-recursively 
                          project-root 
                          (concat "\\." ext "$")
                          nil
                          (lambda (dir)
                            (not (string-match-p "\\(node_modules\\|__pycache__\\|\\.git\\|target\\|build\\)" dir)))))))
    files))

(defun ai-guardian-show-vulnerability-details ()
  "Show detailed information about vulnerability at point."
  (interactive)
  (let* ((filename (buffer-file-name))
         (line-number (line-number-at-pos))
         (vulnerabilities (gethash filename ai-guardian-vulnerabilities)))
    
    (if (not vulnerabilities)
        (ai-guardian--message "No scan results for this file")
      
      (let ((line-vulns (cl-remove-if-not 
                         (lambda (vuln) 
                           (= (cdr (assoc 'line vuln)) line-number))
                         vulnerabilities)))
        
        (if (not line-vulns)
            (ai-guardian--message "No vulnerabilities at current line")
          
          (with-output-to-temp-buffer "*AI Guardian Details*"
            (dolist (vuln line-vulns)
              (princ (format "Type: %s\n" (cdr (assoc 'type vuln))))
              (princ (format "Severity: %s\n" (cdr (assoc 'severity vuln))))
              (princ (format "Description: %s\n" (cdr (assoc 'description vuln))))
              (princ (format "CWE: %s\n" (or (cdr (assoc 'cwe vuln)) "N/A")))
              (when (assoc 'recommendation vuln)
                (princ (format "Recommendation: %s\n" (cdr (assoc 'recommendation vuln)))))
              (princ "\n" (make-string 50 ?-) "\n\n"))))))))

(defun ai-guardian-toggle-auto-scan ()
  "Toggle automatic scanning on file changes."
  (interactive)
  (setq ai-guardian-auto-scan (not ai-guardian-auto-scan))
  (ai-guardian--message "Auto-scan %s" (if ai-guardian-auto-scan "enabled" "disabled"))
  (ai-guardian--update-mode-line))

(defun ai-guardian-clear-results ()
  "Clear all AI Guardian results for current buffer."
  (interactive)
  (when (buffer-file-name)
    (let ((filename (buffer-file-name)))
      (remhash filename ai-guardian-vulnerabilities)
      (ai-guardian--clear-highlights filename)
      (ai-guardian--message "Results cleared"))))

;;; Real-time Monitoring

(defun ai-guardian-start-websocket ()
  "Start WebSocket connection for real-time monitoring."
  (when ai-guardian-websocket
    (websocket-close ai-guardian-websocket))
  
  (setq ai-guardian-websocket
        (websocket-open ai-guardian-websocket-url
                       :on-message #'ai-guardian--handle-websocket-message
                       :on-error #'ai-guardian--handle-websocket-error
                       :on-close #'ai-guardian--handle-websocket-close)))

(defun ai-guardian--handle-websocket-message (websocket frame)
  "Handle WebSocket message from WEBSOCKET with FRAME."
  (let* ((message (json-read-from-string (websocket-frame-text frame)))
         (type (cdr (assoc 'type message))))
    
    (cond
     ((string= type "vulnerability_detected")
      (let ((file (cdr (assoc 'file message)))
            (description (cdr (assoc 'description message))))
        (ai-guardian--message "New vulnerability detected in %s: %s" file description))))))

(defun ai-guardian--handle-websocket-error (websocket type err)
  "Handle WebSocket error."
  (ai-guardian--message "WebSocket error: %s" err))

(defun ai-guardian--handle-websocket-close (websocket)
  "Handle WebSocket close."
  (setq ai-guardian-websocket nil))

;;; Mode Line Integration

(defun ai-guardian--update-mode-line ()
  "Update mode line with vulnerability count."
  (let* ((filename (buffer-file-name))
         (vulnerabilities (when filename (gethash filename ai-guardian-vulnerabilities)))
         (count (if vulnerabilities (length vulnerabilities) 0))
         (status (cond
                  ((= count 0) "✓")
                  ((> count 0) (number-to-string count))
                  (t ""))))
    
    (setq ai-guardian-mode-line-string
          (format ai-guardian-mode-line-format status))))

;;; Flycheck Integration

(when (featurep 'flycheck)
  (flycheck-define-checker ai-guardian
    "AI Guardian security checker."
    :command ("echo" "dummy") ; Dummy command since we use API
    :error-patterns
    ((error line-start (file-name) ":" line ":" column ":" (message) line-end))
    :modes (python-mode js-mode typescript-mode java-mode csharp-mode go-mode rust-mode php-mode ruby-mode swift-mode kotlin-mode c-mode c++-mode))
  
  (defun ai-guardian-flycheck-start (checker callback)
    "Start AI Guardian flycheck with CHECKER and CALLBACK."
    (let* ((filename (buffer-file-name))
           (vulnerabilities (gethash filename ai-guardian-vulnerabilities)))
      
      (when vulnerabilities
        (let ((errors '()))
          (dolist (vuln vulnerabilities)
            (let ((line (cdr (assoc 'line vuln)))
                  (severity (cdr (assoc 'severity vuln)))
                  (description (cdr (assoc 'description vuln)))
                  (type (cdr (assoc 'type vuln))))
              
              (push (flycheck-error-new-at
                     line 1
                     (cond
                      ((member severity '("critical" "high")) 'error)
                      ((string= severity "medium") 'warning)
                      (t 'info))
                     (format "%s: %s" type description)
                     :checker checker)
                    errors)))
          
          (funcall callback 'finished errors)))))
  
  (setf (flycheck-checker-get 'ai-guardian 'start) #'ai-guardian-flycheck-start))

;;; Auto-scan Timer

(defun ai-guardian--schedule-scan ()
  "Schedule a delayed scan."
  (when ai-guardian-scan-timer
    (cancel-timer ai-guardian-scan-timer))
  
  (when ai-guardian-auto-scan
    (setq ai-guardian-scan-timer
          (run-with-timer ai-guardian-scan-delay nil #'ai-guardian-scan-buffer))))

;;; Minor Mode

(defvar ai-guardian-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "C-c g s") #'ai-guardian-scan-buffer)
    (define-key map (kbd "C-c g p") #'ai-guardian-scan-project)
    (define-key map (kbd "C-c g d") #'ai-guardian-show-vulnerability-details)
    (define-key map (kbd "C-c g t") #'ai-guardian-toggle-auto-scan)
    (define-key map (kbd "C-c g c") #'ai-guardian-clear-results)
    map)
  "Keymap for AI Guardian mode.")

;;;###autoload
(define-minor-mode ai-guardian-mode
  "Minor mode for AI Guardian security scanning."
  :lighter (:eval (ai-guardian--update-mode-line))
  :keymap ai-guardian-mode-map
  :group 'ai-guardian
  
  (if ai-guardian-mode
      (progn
        ;; Enable mode
        (add-hook 'after-change-functions #'ai-guardian--on-change nil t)
        (when ai-guardian-scan-on-save
          (add-hook 'after-save-hook #'ai-guardian-scan-buffer nil t))
        (ai-guardian-start-websocket)
        (when (and (featurep 'flycheck) flycheck-mode)
          (add-to-list 'flycheck-checkers 'ai-guardian))
        (ai-guardian--message "AI Guardian mode enabled"))
    
    ;; Disable mode
    (remove-hook 'after-change-functions #'ai-guardian--on-change t)
    (remove-hook 'after-save-hook #'ai-guardian-scan-buffer t)
    (when ai-guardian-websocket
      (websocket-close ai-guardian-websocket))
    (when ai-guardian-scan-timer
      (cancel-timer ai-guardian-scan-timer))
    (ai-guardian--clear-highlights (buffer-file-name))
    (ai-guardian--message "AI Guardian mode disabled")))

(defun ai-guardian--on-change (beg end len)
  "Handle buffer changes from BEG to END with LEN."
  (when ai-guardian-auto-scan
    (ai-guardian--schedule-scan)))

;;;###autoload
(define-globalized-minor-mode global-ai-guardian-mode ai-guardian-mode
  (lambda ()
    (when (and buffer-file-name
               (ai-guardian--get-language-from-filename buffer-file-name)
               (not (string= (ai-guardian--get-language-from-filename buffer-file-name) "unknown")))
      (ai-guardian-mode 1))))

;;; Interactive Commands

;;;###autoload
(defun ai-guardian-enable ()
  "Enable AI Guardian for current buffer."
  (interactive)
  (ai-guardian-mode 1))

;;;###autoload
(defun ai-guardian-disable ()
  "Disable AI Guardian for current buffer."
  (interactive)
  (ai-guardian-mode -1))

(provide 'ai-guardian)

;;; ai-guardian.el ends here

