// Email Analyzer Class
class EmailAnalyzer {
    constructor(emailText) {
        this.text = emailText;
        this.riskFactors = [];
        this.confidence = 0;
        this.verdict = 'VERIFIED';
        this.company = 'Unknown Company';
    }

    // Extract company name from email
    extractCompanyName() {
        const patterns = [
            /(?:from|representing|on behalf of|company|working at|team at)\s+([A-Za-z&\s\.]+?)(?:\s|,|$)/i,
            /([A-Za-z][A-Za-z0-9\s&\.]*(?:Inc|LLC|Ltd|Corp|Company))/i,
        ];

        for (let pattern of patterns) {
            const match = this.text.match(pattern);
            if (match && match[1]) {
                const company = match[1].trim().replace(/\s+/g, ' ');
                if (company.length > 2 && company.length < 100) {
                    this.company = company;
                    return company;
                }
            }
        }

        // Try to extract from sender email
        const emailMatch = this.text.match(/from:\s*([^\s@]+)@([^\s>]+)/i);
        if (emailMatch && emailMatch[2]) {
            this.company = emailMatch[2].split('.')[0];
            return this.company;
        }

        return this.company;
    }

    // Check Grammar Quality
    checkGrammarQuality() {
        const issues = [];

        // Poor grammar patterns
        if (/\b(u r|ur|wanna|gonna|gotta|btw|asap)\b/i.test(this.text)) {
            issues.push({
                name: 'Informal Language',
                reason: 'Uses casual internet slang instead of professional language',
                level: 'low'
            });
        }

        if (/[!?]{2,}/g.test(this.text)) {
            issues.push({
                name: 'Excessive Punctuation',
                reason: 'Multiple consecutive punctuation marks',
                level: 'low'
            });
        }

        if (/\b[A-Z]{5,}\b/g.test(this.text)) {
            issues.push({
                name: 'Unusual Capitalization',
                reason: 'Unusual use of ALL CAPS in words',
                level: 'low'
            });
        }

        // Check for common typos/misspellings
        const typos = /(recieve|occured|succesful|wich|thier)/gi;
        if (typos.test(this.text)) {
            issues.push({
                name: 'Spelling Errors',
                reason: 'Common spelling mistakes detected',
                level: 'low'
            });
        }

        return issues;
    }

    // Check Urgent Language
    checkUrgentLanguage() {
        const urgentKeywords = [
            { word: 'urgent', reason: 'Creates false urgency' },
            { word: 'immediate', reason: 'Demands immediate action' },
            { word: 'act now', reason: 'Pressure tactics' },
            { word: 'limited time', reason: 'Artificial scarcity' },
            { word: "don't wait", reason: 'Urgency language' },
            { word: 'expire', reason: 'Time pressure tactic' },
            { word: 'confirm immediately', reason: 'Demands quick response' },
            { word: 'deadline', reason: 'Artificial deadline' }
        ];

        const textLower = this.text.toLowerCase();
        const found = [];

        for (let item of urgentKeywords) {
            if (textLower.includes(item.word)) {
                found.push({
                    name: 'Urgency Pressure',
                    reason: `Uses "${item.word}" - ${item.reason}`,
                    level: 'low'
                });
            }
        }

        return found;
    }

    // Check Unrealistic Offers
    checkUnrealisticOffer() {
        const issues = [];

        // Salary patterns
        const salaryMatch = this.text.match(/\$\s*([\d,]+)(?:\s*(?:per\s*hour|\/hr|hourly))?/i);
        if (salaryMatch) {
            const amount = parseInt(salaryMatch[1].replace(/,/g, ''));
            if (this.text.toLowerCase().includes('internship') && amount > 100) {
                issues.push({
                    name: 'Unrealistic Compensation',
                    reason: `$${amount}/hour is unusually high for internship`,
                    level: 'medium'
                });
            }
        }

        // No work experience required but high salary
        if (/no experience|fresh graduate|just graduated/.test(this.text) && 
            /\$\s*[\d,]{4,}/.test(this.text)) {
            issues.push({
                name: 'Too Good to Be True',
                reason: 'High pay offered with no experience required',
                level: 'medium'
            });
        }

        // Work from home with high pay
        if (/work from home|remote|wfh/.test(this.text) && 
            /\$\s*[\d,]{5,}/.test(this.text)) {
            issues.push({
                name: 'Suspicious Offer',
                reason: 'Remote internship with exceptionally high salary',
                level: 'medium'
            });
        }

        return issues;
    }

    // Check Suspicious Links
    checkSuspiciousLinks() {
        const issues = [];
        const urlPattern = /https?:\/\/[^\s)>]+/gi;
        const urls = this.text.match(urlPattern) || [];

        const suspiciousPatterns = [
            { pattern: /bit\.ly|tinyurl|short\.link|goo\.gl/, reason: 'URL shortener' },
            { pattern: /\.tk|\.ml|\.cf/, reason: 'Suspicious domain extension' },
            { pattern: /click-here|verify-account|confirm-identity|login|update|verify/, reason: 'Phishing keywords' },
            { pattern: /bit\.|click|shorten|tiny/, reason: 'Suspicious link pattern' }
        ];

        for (let url of urls) {
            for (let item of suspiciousPatterns) {
                if (item.pattern.test(url)) {
                    issues.push({
                        name: 'Suspicious Link',
                        reason: `Shortened or unusual URL: ${url.substring(0, 40)}...`,
                        level: 'high'
                    });
                }
            }
        }

        return issues;
    }

    // Check Domain Inconsistency
    checkDomainInconsistency() {
        const issues = [];

        // Extract sender email and domain
        const emailMatch = this.text.match(/from:\s*[^<]*<([^>@]+@[^>]+)>/i) || 
                          this.text.match(/(?:from|sender|email):\s*([^\s@]+@[^\s>]+)/i);

        if (emailMatch && emailMatch[1]) {
            const senderEmail = emailMatch[1];
            const domain = senderEmail.split('@')[1].toLowerCase();

            // Look for company name
            const companyNameMatch = this.text.match(/(?:from|representing|company|team)\s+([A-Za-z][A-Za-z0-9\s]+?)(?:\s|,|\.|$)/i);
            
            if (companyNameMatch) {
                const company = companyNameMatch[1].toLowerCase().trim();
                const domainName = domain.split('.')[0].toLowerCase();

                // Check if domain matches company
                if (!domainName.includes(company.split(' ')[0]) && 
                    !company.includes(domainName)) {
                    issues.push({
                        name: 'Domain Mismatch',
                        reason: `Sender domain "${domain}" doesn't match claimed company`,
                        level: 'high'
                    });
                }
            }

            // Check for suspicious domain patterns
            if (domain.includes('gmail.com') || domain.includes('yahoo.com') || 
                domain.includes('hotmail.com')) {
                issues.push({
                    name: 'Free Email Domain',
                    reason: `Using free email service (${domain}) instead of company domain`,
                    level: 'high'
                });
            }
        }

        return issues;
    }

    // Check Generic Greeting
    checkGenericGreeting() {
        const issues = [];
        const genericGreetings = [
            'dear candidate',
            'dear applicant',
            'dear user',
            'to whom it may concern',
            'hello there',
            'dear friend',
            'valued member'
        ];

        const textLower = this.text.toLowerCase();
        for (let greeting of genericGreetings) {
            if (textLower.includes(greeting)) {
                issues.push({
                    name: 'Generic Greeting',
                    reason: `Uses generic greeting "${greeting}" instead of your name`,
                    level: 'low'
                });
            }
        }

        return issues;
    }

    // Check Personal Information Request
    checkPersonalInfoRequest() {
        const issues = [];
        const sensitiveRequests = [
            { keyword: 'ssn', reason: 'Requests Social Security Number' },
            { keyword: 'social security', reason: 'Requests Social Security Number' },
            { keyword: 'bank account', reason: 'Requests banking information' },
            { keyword: 'credit card', reason: 'Requests credit card details' },
            { keyword: 'passport', reason: 'Requests passport number' },
            { keyword: 'driver', reason: 'Requests driver\'s license' },
            { keyword: 'verify identity', reason: 'Suspicious identity verification' },
            { keyword: 'confirm identity', reason: 'Suspicious identity verification' }
        ];

        const textLower = this.text.toLowerCase();
        for (let item of sensitiveRequests) {
            if (textLower.includes(item.keyword)) {
                issues.push({
                    name: 'Suspicious Information Request',
                    reason: item.reason,
                    level: 'high'
                });
            }
        }

        return issues;
    }

    // Check Payment Request
    checkPaymentRequest() {
        const issues = [];

        if (/pay|payment|deposit|fee|processing|advance|transfer|wire|western union|money|rupee|dollar/i.test(this.text)) {
            if (/upfront|advance|now|immediately|before|before starting|to start/.test(this.text)) {
                issues.push({
                    name: 'Payment Request',
                    reason: 'Requests payment or money upfront before starting',
                    level: 'high'
                });
            }
        }

        return issues;
    }

    // Check Professional Format
    checkProfessionalFormat() {
        const issues = [];

        // Check for proper email structure
        const hasProperSignature = /regards|sincerely|best|thank you|cheers/i.test(this.text);
        const hasCompanyInfo = /company|department|position|office|address|phone/i.test(this.text);

        if (!hasProperSignature) {
            issues.push({
                name: 'Missing Professional Signature',
                reason: 'No proper sign-off or signature',
                level: 'low'
            });
        }

        if (!hasCompanyInfo) {
            issues.push({
                name: 'Lacks Company Information',
                reason: 'Missing company details, address, or contact info',
                level: 'medium'
            });
        }

        return issues;
    }

    // Main Analysis
    analyze() {
        // Extract company name
        this.extractCompanyName();

        // Run all checks
        this.riskFactors = [
            ...this.checkGrammarQuality(),
            ...this.checkUrgentLanguage(),
            ...this.checkUnrealisticOffer(),
            ...this.checkSuspiciousLinks(),
            ...this.checkDomainInconsistency(),
            ...this.checkGenericGreeting(),
            ...this.checkPersonalInfoRequest(),
            ...this.checkPaymentRequest(),
            ...this.checkProfessionalFormat()
        ];

        // Remove duplicates
        const uniqueFactors = [];
        const seen = new Set();
        for (let factor of this.riskFactors) {
            const key = factor.name + factor.level;
            if (!seen.has(key)) {
                uniqueFactors.push(factor);
                seen.add(key);
            }
        }
        this.riskFactors = uniqueFactors;

        // Calculate verdict
        this.calculateVerdict();

        return {
            verdict: this.verdict,
            confidence: this.confidence,
            company: this.company,
            riskFactors: this.riskFactors,
            recommendation: this.getRecommendation()
        };
    }

    // Calculate Verdict
    calculateVerdict() {
        const highRiskCount = this.riskFactors.filter(r => r.level === 'high').length;
        const mediumRiskCount = this.riskFactors.filter(r => r.level === 'medium').length;
        const lowRiskCount = this.riskFactors.filter(r => r.level === 'low').length;

        if (highRiskCount >= 2 || (highRiskCount >= 1 && mediumRiskCount >= 2)) {
            this.verdict = 'FAKE';
            this.confidence = Math.min(98, 70 + (highRiskCount * 10) + (mediumRiskCount * 5));
        } else if (highRiskCount >= 1 || mediumRiskCount >= 3) {
            this.verdict = 'SUSPICIOUS';
            this.confidence = Math.min(90, 55 + (highRiskCount * 15) + (mediumRiskCount * 8));
        } else if (mediumRiskCount >= 1) {
            this.verdict = 'SUSPICIOUS';
            this.confidence = Math.min(75, 45 + (mediumRiskCount * 10));
        } else {
            this.verdict = 'VERIFIED';
            this.confidence = Math.max(75, 100 - (lowRiskCount * 3));
        }
    }

    // Get Recommendation
    getRecommendation() {
        if (this.verdict === 'FAKE') {
            return '🚨 This email appears to be a SCAM. Do NOT respond, click links, or provide any personal information. Report it to your college/university immediately and to the platform where you found it.';
        } else if (this.verdict === 'SUSPICIOUS') {
            return '⚠️ This email has suspicious characteristics. Before responding, verify the opportunity independently by contacting the company directly through their official website. Never share sensitive information until confirmed.';
        } else {
            return '✅ This email appears legitimate, but always verify by contacting the company directly through their official website before sharing personal information or accepting any offer.';
        }
    }
}

// UI Functions
function analyzeEmail() {
    const emailContent = document.getElementById('emailInput').value.trim();
    const analyzeBtn = document.querySelector('.btn-analyze');
    const btnText = analyzeBtn.querySelector('.btn-text');
    const btnSpinner = analyzeBtn.querySelector('.btn-spinner');

    // Validation
    if (!emailContent) {
        alert('📝 Please paste an email to analyze');
        return;
    }

    if (emailContent.length < 50) {
        document.getElementById('charWarning').style.display = 'inline';
        alert('📧 Please paste the complete email content (at least 50 characters)');
        return;
    }

    if (emailContent.length > 5000) {
        alert('⚠️ Email is too long. Please paste a shorter version.');
        return;
    }

    // Show loading
    document.getElementById('loadingState').style.display = 'flex';
    document.getElementById('resultsSection').style.display = 'none';
    analyzeBtn.disabled = true;
    btnText.style.display = 'none';
    btnSpinner.style.display = 'inline-block';

    // Simulate processing delay (realistic UX)
    setTimeout(() => {
        try {
            const analyzer = new EmailAnalyzer(emailContent);
            const result = analyzer.analyze();

            document.getElementById('loadingState').style.display = 'none';
            displayResults(result);
        } catch (error) {
            console.error('Analysis error:', error);
            alert('❌ Error analyzing email. Please try again.');
            document.getElementById('loadingState').style.display = 'none';
        } finally {
            analyzeBtn.disabled = false;
            btnText.style.display = 'inline';
            btnSpinner.style.display = 'none';
        }
    }, 1500);
}

function displayResults(result) {
    const { verdict, confidence, company, riskFactors, recommendation } = result;
    const resultsCard = document.getElementById('resultsCard');
    const verdictClass = verdict.toLowerCase();

    let verdictIcon = '✅';
    let verdictText = 'VERIFIED';
    if (verdict === 'SUSPICIOUS') {
        verdictIcon = '⚠️';
        verdictText = 'SUSPICIOUS';
    } else if (verdict === 'FAKE') {
        verdictIcon = '❌';
        verdictText = 'FAKE';
    }

    let riskFactorsHTML = '';
    if (riskFactors.length > 0) {
        riskFactors.forEach(factor => {
            riskFactorsHTML += `
                <div class="risk-item ${factor.level}">
                    <strong>${factor.name}</strong>
                    <p>${factor.reason}</p>
                    <span class="risk-level ${factor.level}">${factor.level.toUpperCase()}</span>
                </div>
            `;
        });
    }

    resultsCard.innerHTML = `
        <div class="verdict-badge ${verdictClass}">${verdictIcon} ${verdictText}</div>
        
        <h3 style="text-align: left; margin: 1.5rem 0 1rem 0; font-size: 1.5rem;">
            ${company}
        </h3>

        <div class="confidence-score">
            <strong>Analysis Confidence Score</strong>
            <div class="confidence-bar">
                <div class="confidence-fill" style="width: ${confidence}%"></div>
            </div>
            <div class="confidence-percentage">${confidence}% Confidence</div>
        </div>

        ${riskFactors.length > 0 ? `
            <div class="risk-factors">
                <h4>🔴 Detected Risk Factors (${riskFactors.length})</h4>
                ${riskFactorsHTML}
            </div>
        ` : `
            <div class="risk-factors">
                <h4>✅ No Major Risk Factors Detected</h4>
                <p>This email passed our security checks.</p>
            </div>
        `}

        <div class="recommendation">
            <strong>💡 Our Recommendation:</strong>
            <p>${recommendation}</p>
        </div>
    `;

    resultsCard.classList.remove('verified', 'fake', 'suspicious');
    resultsCard.classList.add(verdictClass);

    document.getElementById('resultsSection').style.display = 'block';

    // Scroll to results
    setTimeout(() => {
        document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
}

function resetAnalyzer() {
    document.getElementById('emailInput').value = '';
    document.getElementById('charCount').textContent = '0';
    document.getElementById('charWarning').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('loadingState').style.display = 'none';
    document.getElementById('emailInput').focus();
}

// Character Counter
document.addEventListener('DOMContentLoaded', () => {
    const emailInput = document.getElementById('emailInput');
    const charCount = document.getElementById('charCount');
    const charWarning = document.getElementById('charWarning');

    emailInput.addEventListener('input', (e) => {
        const length = e.target.value.length;
        charCount.textContent = length;

        if (length < 50 && length > 0) {
            charWarning.style.display = 'inline';
        } else {
            charWarning.style.display = 'none';
        }
    });

    // Theme Toggle
    const themeToggle = document.getElementById('themeToggle');
    const savedTheme = localStorage.getItem('theme') || 'light';

    if (savedTheme === 'dark') {
        document.body.classList.add('dark-mode');
        themeToggle.textContent = '☀️';
    }

    themeToggle.addEventListener('click', () => {
        document.body.classList.toggle('dark-mode');
        const isDark = document.body.classList.contains('dark-mode');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        themeToggle.textContent = isDark ? '☀️' : '🌙';
    });
});