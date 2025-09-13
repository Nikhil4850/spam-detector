// Spam Detection Algorithm
class SpamDetector {
    constructor() {
        // Spam keywords with different weight categories
        this.spamKeywords = {
            high: [
                'winner', 'congratulations', 'lottery', 'prize', 'jackpot',
                'million', 'billion', 'inheritance', 'beneficiary', 'urgent',
                'immediately', 'act now', 'limited time', 'expires today',
                'click here', 'click now', 'free money', 'easy money',
                'guaranteed', 'risk free', 'no risk', 'investment opportunity',
                'make money fast', 'work from home', 'earn extra income',
                'debt free', 'credit repair', 'loan approved', 'pre-approved',
                'viagra', 'pharmacy', 'prescription', 'weight loss',
                'lose weight', 'diet pills', 'miracle cure'
            ],
            medium: [
                'free', 'offer', 'deal', 'discount', 'save', 'cheap',
                'affordable', 'promotion', 'special', 'limited',
                'exclusive', 'bonus', 'gift', 'reward', 'cash',
                'money', 'income', 'profit', 'earn', 'win',
                'opportunity', 'business', 'investment', 'loan',
                'credit', 'mortgage', 'insurance', 'claim'
            ],
            low: [
                'buy', 'purchase', 'order', 'subscribe', 'register',
                'sign up', 'join', 'membership', 'account', 'service',
                'product', 'company', 'website', 'online', 'internet',
                'email', 'message', 'notification', 'alert', 'update'
            ]
        };

        // Spam patterns (regex)
        this.spamPatterns = [
            /\b\d+%\s*(off|discount|save)\b/i,
            /\$\d+(\.\d{2})?\s*(free|bonus|gift)/i,
            /call\s*now\s*\d{3}[-.\s]?\d{3}[-.\s]?\d{4}/i,
            /click\s*(here|now|this|link)/i,
            /act\s*now\s*(!|\.){0,3}/i,
            /limited\s*time\s*(offer|deal)/i,
            /\b(urgent|immediate|asap)\b.*\b(action|response|reply)\b/i,
            /\b(congratulations?|congrats)\b.*\b(won|winner|selected)\b/i,
            /\b(free|no\s*cost).*\b(trial|sample|gift|bonus)\b/i,
            /\bmillion\s*(dollar|pound|euro)s?\b/i
        ];

        // Suspicious formatting patterns
        this.suspiciousFormatting = [
            /[A-Z]{5,}/g, // Excessive caps
            /!{3,}/g, // Multiple exclamation marks
            /\${2,}/g, // Multiple dollar signs
            /\*{2,}/g, // Multiple asterisks
            /#{2,}/g  // Multiple hash symbols
        ];
    }

    // Main spam detection method
    detectSpam(message) {
        if (!message || message.trim().length === 0) {
            return {
                isSpam: false,
                confidence: 0,
                reasons: [],
                score: 0
            };
        }

        const normalizedMessage = message.toLowerCase().trim();
        let spamScore = 0;
        const reasons = [];
        const maxScore = 100;

        // Check for spam keywords
        const keywordResults = this.checkKeywords(normalizedMessage);
        spamScore += keywordResults.score;
        reasons.push(...keywordResults.reasons);

        // Check for spam patterns
        const patternResults = this.checkPatterns(message);
        spamScore += patternResults.score;
        reasons.push(...patternResults.reasons);

        // Check for suspicious formatting
        const formattingResults = this.checkFormatting(message);
        spamScore += formattingResults.score;
        reasons.push(...formattingResults.reasons);

        // Check message length and structure
        const structureResults = this.checkStructure(message);
        spamScore += structureResults.score;
        reasons.push(...structureResults.reasons);

        // Normalize score to percentage
        const confidence = Math.min(Math.round((spamScore / maxScore) * 100), 100);
        const isSpam = confidence >= 60; // Threshold for spam classification

        return {
            isSpam,
            confidence,
            reasons: reasons.slice(0, 5), // Limit to top 5 reasons
            score: spamScore
        };
    }

    // Check for spam keywords
    checkKeywords(message) {
        let score = 0;
        const reasons = [];
        const foundKeywords = [];

        // Check high-weight keywords
        this.spamKeywords.high.forEach(keyword => {
            if (message.includes(keyword)) {
                score += 25;
                foundKeywords.push(keyword);
            }
        });

        // Check medium-weight keywords
        this.spamKeywords.medium.forEach(keyword => {
            if (message.includes(keyword)) {
                score += 10;
                foundKeywords.push(keyword);
            }
        });

        // Check low-weight keywords
        this.spamKeywords.low.forEach(keyword => {
            if (message.includes(keyword)) {
                score += 3;
                foundKeywords.push(keyword);
            }
        });

        if (foundKeywords.length > 0) {
            reasons.push(`Contains spam keywords: ${foundKeywords.slice(0, 3).join(', ')}`);
        }

        // Bonus score for multiple keywords
        if (foundKeywords.length >= 3) {
            score += 15;
            reasons.push(`Multiple spam keywords detected (${foundKeywords.length})`);
        }

        return { score, reasons };
    }

    // Check for spam patterns
    checkPatterns(message) {
        let score = 0;
        const reasons = [];

        this.spamPatterns.forEach((pattern, index) => {
            if (pattern.test(message)) {
                score += 20;
                switch (index) {
                    case 0:
                        reasons.push('Contains percentage discount pattern');
                        break;
                    case 1:
                        reasons.push('Contains money offer pattern');
                        break;
                    case 2:
                        reasons.push('Contains phone number with call-to-action');
                        break;
                    case 3:
                        reasons.push('Contains suspicious click request');
                        break;
                    case 4:
                        reasons.push('Contains urgent action request');
                        break;
                    case 5:
                        reasons.push('Contains limited time offer');
                        break;
                    case 6:
                        reasons.push('Contains urgent response request');
                        break;
                    case 7:
                        reasons.push('Contains winner/congratulations pattern');
                        break;
                    case 8:
                        reasons.push('Contains free offer pattern');
                        break;
                    case 9:
                        reasons.push('Contains large money amount');
                        break;
                }
            }
        });

        return { score, reasons };
    }

    // Check for suspicious formatting
    checkFormatting(message) {
        let score = 0;
        const reasons = [];

        this.suspiciousFormatting.forEach((pattern, index) => {
            const matches = message.match(pattern);
            if (matches) {
                score += matches.length * 5;
                switch (index) {
                    case 0:
                        reasons.push('Excessive use of capital letters');
                        break;
                    case 1:
                        reasons.push('Multiple exclamation marks');
                        break;
                    case 2:
                        reasons.push('Multiple dollar signs');
                        break;
                    case 3:
                        reasons.push('Excessive asterisks or emphasis');
                        break;
                    case 4:
                        reasons.push('Multiple hash symbols');
                        break;
                }
            }
        });

        return { score, reasons };
    }

    // Check message structure
    checkStructure(message) {
        let score = 0;
        const reasons = [];

        // Very short messages with keywords are suspicious
        if (message.length < 50 && this.checkKeywords(message.toLowerCase()).score > 0) {
            score += 10;
            reasons.push('Short message with spam indicators');
        }

        // Messages with many URLs
        const urlPattern = /(https?:\/\/[^\s]+)/gi;
        const urls = message.match(urlPattern);
        if (urls && urls.length > 2) {
            score += 15;
            reasons.push('Contains multiple URLs');
        }

        // Messages with phone numbers
        const phonePattern = /\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
        const phones = message.match(phonePattern);
        if (phones && phones.length > 0) {
            score += 8;
            reasons.push('Contains phone number');
        }

        // Messages with email addresses
        const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
        const emails = message.match(emailPattern);
        if (emails && emails.length > 1) {
            score += 10;
            reasons.push('Contains multiple email addresses');
        }

        return { score, reasons };
    }
}

// UI Controller
class UIController {
    constructor() {
        this.spamDetector = new SpamDetector();
        this.initializeElements();
        this.bindEvents();
        this.initializeAnimations();
    }

    initializeElements() {
        // Main elements
        this.messageInput = document.getElementById('message-input');
        this.checkButton = document.getElementById('check-spam-btn');
        this.resultSection = document.getElementById('result-section');
        this.resultCard = document.getElementById('result-card');
        this.resultIcon = document.getElementById('result-icon');
        this.resultTitle = document.getElementById('result-title');
        this.resultDescription = document.getElementById('result-description');
        this.confidenceFill = document.getElementById('confidence-fill');
        this.confidenceText = document.getElementById('confidence-text');

        // Navigation elements
        this.hamburger = document.querySelector('.hamburger');
        this.navMenu = document.querySelector('.nav-menu');
        this.navLinks = document.querySelectorAll('.nav-link');

        // Contact form
        this.contactForm = document.getElementById('contact-form');
    }

    bindEvents() {
        // Spam detection
        this.checkButton.addEventListener('click', () => this.checkSpam());
        this.messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && e.ctrlKey) {
                this.checkSpam();
            }
        });

        // Navigation
        this.hamburger.addEventListener('click', () => this.toggleMobileMenu());
        this.navLinks.forEach(link => {
            link.addEventListener('click', () => this.closeMobileMenu());
        });

        // Smooth scrolling for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', (e) => {
                e.preventDefault();
                const target = document.querySelector(anchor.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });

        // Contact form
        if (this.contactForm) {
            this.contactForm.addEventListener('submit', (e) => this.handleContactForm(e));
        }

        // Scroll effects
        window.addEventListener('scroll', () => this.handleScroll());
    }

    initializeAnimations() {
        // Add floating particles
        this.createFloatingParticles();
        
        // Initialize intersection observer for animations
        this.initializeScrollAnimations();
    }

    // Spam detection functionality
    async checkSpam() {
        const message = this.messageInput.value.trim();
        
        if (!message) {
            this.showError('Please enter a message to analyze.');
            return;
        }

        // Show loading state
        this.setLoadingState(true);

        // Simulate API delay for better UX
        await this.delay(800);

        try {
            const result = this.spamDetector.detectSpam(message);
            this.displayResult(result);
        } catch (error) {
            this.showError('An error occurred while analyzing the message.');
            console.error('Spam detection error:', error);
        } finally {
            this.setLoadingState(false);
        }
    }

    displayResult(result) {
        const { isSpam, confidence, reasons } = result;

        // Update result card classes
        this.resultCard.className = 'result-card';
        this.resultIcon.className = 'result-icon';

        if (isSpam) {
            this.resultCard.classList.add('spam');
            this.resultIcon.classList.add('spam');
            this.resultIcon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
            this.resultTitle.textContent = '🚨 Spam Detected';
            this.resultTitle.style.color = 'var(--danger-red)';
            this.resultDescription.textContent = reasons.length > 0 
                ? `This message appears to be spam. ${reasons.join('. ')}.`
                : 'This message contains characteristics commonly found in spam messages.';
        } else {
            this.resultCard.classList.add('safe');
            this.resultIcon.classList.add('safe');
            this.resultIcon.innerHTML = '<i class="fas fa-check-circle"></i>';
            this.resultTitle.textContent = '✅ Safe Message';
            this.resultTitle.style.color = 'var(--success-green)';
            this.resultDescription.textContent = confidence > 30
                ? 'This message appears to be legitimate, though it contains some promotional language.'
                : 'This message appears to be safe and legitimate.';
        }

        // Update confidence meter
        this.updateConfidenceMeter(confidence);

        // Add entrance animation
        this.resultCard.style.opacity = '0';
        this.resultCard.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            this.resultCard.style.transition = 'all 0.5s ease';
            this.resultCard.style.opacity = '1';
            this.resultCard.style.transform = 'translateY(0)';
        }, 100);
    }

    updateConfidenceMeter(confidence) {
        // Animate confidence bar
        this.confidenceFill.style.width = '0%';
        this.confidenceText.textContent = '0%';

        setTimeout(() => {
            this.confidenceFill.style.width = `${confidence}%`;
            
            // Animate counter
            this.animateCounter(0, confidence, 1000, (value) => {
                this.confidenceText.textContent = `${Math.round(value)}%`;
            });

            // Change color based on confidence level
            if (confidence >= 80) {
                this.confidenceFill.style.background = 'linear-gradient(90deg, var(--danger-red), #ff6666)';
            } else if (confidence >= 60) {
                this.confidenceFill.style.background = 'linear-gradient(90deg, var(--warning-orange), #ffaa44)';
            } else if (confidence >= 30) {
                this.confidenceFill.style.background = 'linear-gradient(90deg, var(--warning-orange), var(--primary-cyan))';
            } else {
                this.confidenceFill.style.background = 'linear-gradient(90deg, var(--success-green), var(--primary-cyan))';
            }
        }, 200);
    }

    setLoadingState(loading) {
        if (loading) {
            this.checkButton.classList.add('loading');
            this.checkButton.innerHTML = '<i class="fas fa-spinner"></i> Analyzing...';
            this.checkButton.disabled = true;
        } else {
            this.checkButton.classList.remove('loading');
            this.checkButton.innerHTML = '<i class="fas fa-search"></i> Check for Spam';
            this.checkButton.disabled = false;
        }
    }

    showError(message) {
        this.resultCard.className = 'result-card';
        this.resultIcon.className = 'result-icon';
        this.resultIcon.innerHTML = '<i class="fas fa-exclamation-circle"></i>';
        this.resultTitle.textContent = 'Error';
        this.resultTitle.style.color = 'var(--danger-red)';
        this.resultDescription.textContent = message;
        this.confidenceFill.style.width = '0%';
        this.confidenceText.textContent = '0%';
    }

    // Navigation functionality
    toggleMobileMenu() {
        this.hamburger.classList.toggle('active');
        this.navMenu.classList.toggle('active');
    }

    closeMobileMenu() {
        this.hamburger.classList.remove('active');
        this.navMenu.classList.remove('active');
    }

    // Contact form handling
    async handleContactForm(e) {
        e.preventDefault();
        
        const submitBtn = e.target.querySelector('.submit-btn');
        const originalText = submitBtn.innerHTML;
        
        // Show loading state
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
        submitBtn.disabled = true;

        // Simulate form submission
        await this.delay(2000);

        // Show success message
        submitBtn.innerHTML = '<i class="fas fa-check"></i> Message Sent!';
        submitBtn.style.background = 'linear-gradient(45deg, var(--success-green), var(--primary-cyan))';

        // Reset form
        setTimeout(() => {
            e.target.reset();
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
            submitBtn.style.background = '';
        }, 3000);
    }

    // Scroll effects
    handleScroll() {
        const navbar = document.querySelector('.navbar');
        if (window.scrollY > 100) {
            navbar.style.background = 'rgba(10, 10, 10, 0.98)';
            navbar.style.boxShadow = '0 2px 20px rgba(0, 255, 255, 0.1)';
        } else {
            navbar.style.background = 'rgba(10, 10, 10, 0.95)';
            navbar.style.boxShadow = 'none';
        }
    }

    // Animation utilities
    createFloatingParticles() {
        const particlesContainer = document.querySelector('.floating-particles');
        const particleCount = 15;

        for (let i = 0; i < particleCount; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.cssText = `
                position: absolute;
                width: ${Math.random() * 4 + 2}px;
                height: ${Math.random() * 4 + 2}px;
                background: var(--primary-cyan);
                border-radius: 50%;
                box-shadow: var(--glow-cyan);
                left: ${Math.random() * 100}%;
                top: ${Math.random() * 100}%;
                animation: float ${Math.random() * 10 + 5}s ease-in-out infinite;
                animation-delay: ${Math.random() * 5}s;
                opacity: ${Math.random() * 0.5 + 0.3};
            `;
            particlesContainer.appendChild(particle);
        }
    }

    initializeScrollAnimations() {
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        }, observerOptions);

        // Observe elements for scroll animations
        document.querySelectorAll('.feature-card, .step, .result-card').forEach(el => {
            el.style.opacity = '0';
            el.style.transform = 'translateY(30px)';
            el.style.transition = 'all 0.6s ease';
            observer.observe(el);
        });
    }

    animateCounter(start, end, duration, callback) {
        const startTime = performance.now();
        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const easeOutQuart = 1 - Math.pow(1 - progress, 4);
            const current = start + (end - start) * easeOutQuart;
            
            callback(current);
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };
        requestAnimationFrame(animate);
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Sample messages for testing
const sampleMessages = {
    spam: [
        "CONGRATULATIONS! You've won $1,000,000! Click here immediately to claim your prize before it expires!",
        "URGENT: Your account will be closed! Click this link now to verify your information and save your account.",
        "FREE MONEY! Earn $500 per day working from home! No experience needed! Call now: 555-123-4567",
        "You have been selected as a winner in our lottery! Claim your inheritance of $2 million dollars now!",
        "AMAZING DEAL! 90% OFF everything! Limited time offer! Buy now or miss out forever! Click here!"
    ],
    safe: [
        "Hi, just wanted to check if we're still meeting for lunch tomorrow at 12 PM. Let me know!",
        "Thank you for your purchase. Your order #12345 has been shipped and will arrive in 3-5 business days.",
        "Reminder: Your appointment with Dr. Smith is scheduled for tomorrow at 2 PM. Please arrive 15 minutes early.",
        "Happy birthday! Hope you have a wonderful day celebrating with family and friends.",
        "The meeting has been moved to Conference Room B. See you there at 3 PM."
    ]
};

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    const app = new UIController();
    
    // Add sample message functionality for testing
    if (window.location.hash === '#demo') {
        const messageInput = document.getElementById('message-input');
        const addSampleBtn = document.createElement('button');
        addSampleBtn.textContent = 'Try Sample Message';
        addSampleBtn.className = 'sample-btn';
        addSampleBtn.style.cssText = `
            margin-top: 10px;
            padding: 8px 16px;
            background: var(--accent-purple);
            color: white;
            border: none;
            border-radius: 20px;
            cursor: pointer;
            font-size: 0.9rem;
        `;
        
        addSampleBtn.addEventListener('click', () => {
            const allSamples = [...sampleMessages.spam, ...sampleMessages.safe];
            const randomSample = allSamples[Math.floor(Math.random() * allSamples.length)];
            messageInput.value = randomSample;
        });
        
        messageInput.parentNode.appendChild(addSampleBtn);
    }

    console.log('🛡️ CyberRAR Spam Shield initialized successfully!');
});
