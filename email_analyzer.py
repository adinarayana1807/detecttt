import re
import json
from datetime import datetime
from bs4 import BeautifulSoup
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import openai
import os
from dotenv import load_dotenv

load_dotenv()

# Configure OpenAI
openai.api_key = os.getenv('OPENAI_API_KEY')

class EmailAnalyzer:
    def __init__(self):
        self.risk_factors = []
        self.confidence = 0
        self.verdict = 'VERIFIED'
        self.company_name = 'Unknown'
        
    def extract_domain(self, email):
        """Extract domain from email address"""
        match = re.search(r'@([\w\.-]+)', email)
        return match.group(1) if match else None
    
    def check_grammar_quality(self, text):
        """Check for grammar and spelling issues"""
        issues = 0
        
        # Common mistakes
        patterns = [
            (r'\b(u r|ur|wanna|gonna|gotta|btw|asap)\b', 'Informal language'),
            (r'[A-Z]{2,}\s[A-Z]{2,}', 'Multiple caps'),
            (r'\s{2,}', 'Multiple spaces'),
            (r'[!?]{2,}', 'Multiple punctuation'),
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                issues += 1
                self.risk_factors.append({
                    'name': 'Grammar Issue',
                    'reason': desc,
                    'level': 'low'
                })
        
        return issues
    
    def check_urgent_language(self, text):
        """Check for pressure tactics and urgency"""
        urgent_keywords = [
            'urgent', 'immediate', 'act now', 'limited time', 'immediately',
            'asap', 'deadline', 'hurry', 'don\'t wait', 'expire', 'confirm immediately'
        ]
        
        text_lower = text.lower()
        for keyword in urgent_keywords:
            if keyword in text_lower:
                self.risk_factors.append({
                    'name': 'Urgency Pressure',
                    'reason': f'Uses "{keyword}" to create pressure',
                    'level': 'low'
                })
                return True
        
        return False
    
    def check_unrealistic_offer(self, text):
        """Check for unrealistic compensation"""
        salary_patterns = [
            (r'\$\s*(\d+,\d+|\d{4,})\s*hour', 'Per hour'),
            (r'\$\s*(\d+,\d+,\d+|\d{7,})\s*year', 'Per year'),
        ]
        
        for pattern, desc in salary_patterns:
            match = re.search(pattern, text)
            if match:
                amount = match.group(1).replace(',', '')
                try:
                    salary = int(amount)
                    # Check if unrealistic for internship
                    if 'internship' in text.lower() and salary > 100000:
                        self.risk_factors.append({
                            'name': 'Unrealistic Compensation',
                            'reason': f'Internship salary of ${amount}/year is unusually high',
                            'level': 'medium'
                        })
                        return True
                except:
                    pass
        
        return False
    
    def check_suspicious_links(self, text):
        """Check for suspicious links"""
        url_pattern = r'https?://[^\s)]+'
        urls = re.findall(url_pattern, text)
        
        suspicious_patterns = [
            'bit.ly', 'tinyurl', 'short.link', '.tk', '.ml',
            'click-here', 'verify-account', 'confirm-identity'
        ]
        
        for url in urls:
            url_lower = url.lower()
            for pattern in suspicious_patterns:
                if pattern in url_lower:
                    self.risk_factors.append({
                        'name': 'Suspicious Link',
                        'reason': f'URL pattern "{pattern}" detected',
                        'level': 'high'
                    })
                    return True
        
        return False
    
    def check_domain_inconsistency(self, text):
        """Check for domain inconsistencies"""
        # Extract email and company mentions
        email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', text)
        
        if email_match:
            sender_domain = email_match.group(1).lower()
            
            # Look for company names
            company_keywords = ['company', 'work', 'organization', 'team']
            for keyword in company_keywords:
                for match in re.finditer(rf'{keyword}\s+(\w+)', text, re.IGNORECASE):
                    company = match.group(1).lower()
                    if company not in sender_domain and len(company) > 2:
                        self.company_name = company.capitalize()
                        if not self._domain_matches_company(sender_domain, company):
                            self.risk_factors.append({
                                'name': 'Domain Mismatch',
                                'reason': f'Sender domain "{sender_domain}" doesn\'t match "{company}"',
                                'level': 'high'
                            })
                            return True
        
        return False
    
    def _domain_matches_company(self, domain, company):
        """Check if domain matches company name"""
        domain_clean = domain.replace('.com', '').replace('.co', '').replace('.org', '')
        return company.lower() in domain_clean.lower() or domain_clean.lower() in company.lower()
    
    def check_generic_greeting(self, text):
        """Check for generic greetings"""
        generic_greetings = [
            'dear candidate', 'dear applicant', 'dear user',
            'to whom it may concern', 'hello there'
        ]
        
        text_lower = text.lower()
        for greeting in generic_greetings:
            if greeting in text_lower:
                self.risk_factors.append({
                    'name': 'Generic Greeting',
                    'reason': f'Uses generic greeting "{greeting}" instead of personal name',
                    'level': 'low'
                })
                return True
        
        return False
    
    def check_personal_info_request(self, text):
        """Check for suspicious personal info requests"""
        sensitive_requests = [
            'ssn', 'social security', 'bank account', 'credit card',
            'passport', 'driver\'s license', 'verify your identity'
        ]
        
        text_lower = text.lower()
        for request in sensitive_requests:
            if request in text_lower:
                self.risk_factors.append({
                    'name': 'Suspicious Info Request',
                    'reason': f'Requests sensitive information: {request}',
                    'level': 'high'
                })
                return True
        
        return False
    
    def ai_semantic_analysis(self, text):
        """Use OpenAI for semantic analysis"""
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert at identifying fake internship emails. Analyze the following email and determine if it's legitimate, suspicious, or fake. Also identify red flags."
                    },
                    {
                        "role": "user",
                        "content": f"Analyze this email:\n\n{text[:1000]}\n\nRespond in JSON format: {{'assessment': 'legitimate/suspicious/fake', 'confidence': 0-100, 'red_flags': []}}"
                    }
                ],
                temperature=0.3
            )
            
            result_text = response.choices[0].message.content
            # Parse JSON response
            try:
                ai_result = json.loads(result_text)
                return ai_result
            except:
                # Try to extract JSON from response
                import json
                json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
                return None
                
        except Exception as e:
            print(f"AI analysis error: {str(e)}")
            return None
    
    def calculate_verdict(self):
        """Calculate final verdict based on risk factors"""
        high_risk_count = sum(1 for r in self.risk_factors if r.get('level') == 'high')
        medium_risk_count = sum(1 for r in self.risk_factors if r.get('level') == 'medium')
        
        # Scoring logic
        if high_risk_count >= 2 or (high_risk_count >= 1 and medium_risk_count >= 2):
            self.verdict = 'FAKE'
            self.confidence = min(95, 60 + (high_risk_count * 15) + (medium_risk_count * 5))
        elif high_risk_count >= 1 or medium_risk_count >= 3:
            self.verdict = 'SUSPICIOUS'
            self.confidence = min(85, 50 + (high_risk_count * 20) + (medium_risk_count * 8))
        else:
            self.verdict = 'VERIFIED'
            self.confidence = max(70, 100 - (len(self.risk_factors) * 5))
    
    def get_recommendation(self):
        """Get user recommendation based on verdict"""
        if self.verdict == 'FAKE':
            return "This email appears to be a scam. Do NOT respond or provide any personal information. Report it to your college/university and the platform where you found it."
        elif self.verdict == 'SUSPICIOUS':
            return "This email has some questionable characteristics. Verify the sender independently by contacting the company directly through their official website before responding."
        else:
            return "This email appears to be legitimate. However, always verify through official company channels and never share sensitive information until you've confirmed the opportunity."

def analyze_email_content(email_text):
    """Main analysis function"""
    analyzer = EmailAnalyzer()
    
    # Run all checks
    analyzer.check_grammar_quality(email_text)
    analyzer.check_urgent_language(email_text)
    analyzer.check_unrealistic_offer(email_text)
    analyzer.check_suspicious_links(email_text)
    analyzer.check_domain_inconsistency(email_text)
    analyzer.check_generic_greeting(email_text)
    analyzer.check_personal_info_request(email_text)
    
    # AI analysis (optional, comment out if no OpenAI key)
    try:
        ai_result = analyzer.ai_semantic_analysis(email_text)
        if ai_result and ai_result.get('red_flags'):
            for flag in ai_result['red_flags']:
                analyzer.risk_factors.append({
                    'name': 'AI Detected Issue',
                    'reason': flag,
                    'level': 'medium'
                })
    except:
        pass
    
    # Calculate final verdict
    analyzer.calculate_verdict()
    
    return {
        'verdict': analyzer.verdict,
        'confidence': analyzer.confidence,
        'company': analyzer.company_name,
        'riskFactors': analyzer.risk_factors,
        'recommendation': analyzer.get_recommendation()
    }