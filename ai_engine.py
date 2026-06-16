"""
ai_engine.py - AI Threat Analysis Engine for AI-NIDS

Integrates with Ollama running Llama 3 locally to provide
intelligent threat explanations, risk assessments, and
mitigation recommendations for detected security alerts.
"""

import requests
import json
import logging

logger = logging.getLogger(__name__)


class AIEngine:
    """AI-powered threat analysis engine using Ollama/Llama 3."""

    def __init__(self, model='llama3.1:8b', base_url='http://localhost:11434'):
        """
        Initialize the AI engine.

        Args:
            model: Ollama model name (default: llama3)
            base_url: Ollama API base URL
        """
        self.model = model
        self.base_url = base_url.rstrip('/')
        self.timeout = 60  # seconds
        self.max_retries = 2

    def is_available(self):
        """
        Check if Ollama is running and the model (or a compatible one) is available.

        Returns:
            Boolean indicating availability
        """
        try:
            response = requests.get(f'{self.base_url}/api/tags', timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                model_names = [m.get('name', '') for m in models]
                
                # Try exact/split match first
                for name in model_names:
                    if name == self.model or name.split(':')[0] == self.model:
                        return True
                
                # Try prefix match to support llama3.1, llama3.2, etc.
                for name in model_names:
                    base = name.split(':')[0]
                    if base.startswith('llama3') or base.startswith('llama'):
                        self.model = name  # Switch to installed version
                        logger.info(f"Dynamically switched to installed model: {name}")
                        return True
            return False
        except (requests.ConnectionError, requests.Timeout):
            return False
        except Exception as e:
            logger.error(f"Error checking Ollama availability: {e}")
            return False

    def analyze_alert(self, alert):
        """
        Analyze a security alert using Llama 3.

        Args:
            alert: Dictionary containing alert details

        Returns:
            String with the AI analysis, or an error message
        """
        prompt = self._build_prompt(alert)

        for attempt in range(self.max_retries + 1):
            try:
                result = self._query_ollama(prompt)
                if result:
                    return result
            except requests.ConnectionError:
                logger.warning(f"Ollama connection failed (attempt {attempt + 1})")
                if attempt == self.max_retries:
                    return self._fallback_analysis(alert)
            except requests.Timeout:
                logger.warning(f"Ollama request timed out (attempt {attempt + 1})")
                if attempt == self.max_retries:
                    return self._fallback_analysis(alert)
            except Exception as e:
                logger.error(f"AI analysis error: {e}")
                return self._fallback_analysis(alert)

        return self._fallback_analysis(alert)

    def _build_prompt(self, alert):
        """
        Build a structured security analysis prompt.

        Args:
            alert: Dictionary containing alert details

        Returns:
            Formatted prompt string
        """
        return f"""You are an expert cybersecurity analyst working in a Security Operations Center (SOC). 
Analyze the following network intrusion detection alert and provide a detailed security assessment.

=== ALERT DETAILS ===
Signature: {alert.get('signature', 'Unknown')}
Category: {alert.get('category', 'Unknown')}
Severity: {alert.get('severity_label', 'Unknown')} (Level {alert.get('severity', 'N/A')})
Source IP: {alert.get('src_ip', 'Unknown')}
Source Port: {alert.get('src_port', 'Unknown')}
Destination IP: {alert.get('dest_ip', 'Unknown')}
Destination Port: {alert.get('dest_port', 'Unknown')}
Protocol: {alert.get('protocol', 'Unknown')}
Timestamp: {alert.get('timestamp', 'Unknown')}
=====================

Provide your analysis in the following format:

## Threat Explanation
Explain what this alert means in plain language. What is the attacker likely trying to do?

## Risk Level
Assess the risk level: Critical, High, Medium, or Low. Justify your assessment.

## Attack Vector
Describe the attack technique and method being used.

## Potential Impact
What could happen if this attack succeeds?

## Recommendations
Provide 3-5 specific, actionable mitigation steps to address this threat.

## Indicators of Compromise (IOCs)
List any relevant IOCs from this alert.

Be concise but thorough. Focus on actionable intelligence."""

    def _query_ollama(self, prompt):
        """
        Send a prompt to Ollama and get the response.

        Args:
            prompt: The analysis prompt

        Returns:
            Response text from the model
        """
        payload = {
            'model': self.model,
            'prompt': prompt,
            'stream': False,
            'options': {
                'temperature': 0.3,
                'top_p': 0.9,
                'num_predict': 1024
            }
        }

        response = requests.post(
            f'{self.base_url}/api/generate',
            json=payload,
            timeout=self.timeout
        )

        if response.status_code == 200:
            data = response.json()
            return data.get('response', '').strip()
        else:
            logger.error(f"Ollama returned status {response.status_code}: {response.text}")
            return None

    def _fallback_analysis(self, alert):
        """
        Generate a basic analysis when Ollama is unavailable.

        Args:
            alert: Dictionary containing alert details

        Returns:
            Formatted fallback analysis string
        """
        severity = alert.get('severity_label', 'Unknown')
        signature = alert.get('signature', 'Unknown Alert')
        src_ip = alert.get('src_ip', 'Unknown')
        dest_ip = alert.get('dest_ip', 'Unknown')
        category = alert.get('category', 'Unknown')

        # Basic analysis based on severity and category
        risk_map = {'High': 'High', 'Medium': 'Medium', 'Low': 'Low'}
        risk = risk_map.get(severity, 'Medium')

        analysis = f"""## Threat Explanation
A network security event has been detected: **{signature}**
This alert falls under the category of **{category}** and was triggered by traffic from {src_ip} to {dest_ip}.

## Risk Level
**{risk}** — This assessment is based on the Suricata severity classification.

## Attack Vector
The alert indicates potential malicious activity categorized as {category}. 
The specific technique involves the signature pattern: {signature}.

## Potential Impact
If this activity is malicious, it could lead to:
- Unauthorized access to network resources
- Data exfiltration or manipulation
- Further exploitation of network services
- Lateral movement within the network

## Recommendations
1. Investigate the source IP ({src_ip}) for suspicious behavior patterns
2. Review firewall logs for related traffic from this source
3. Check if destination services on {dest_ip} are properly hardened
4. Consider temporarily blocking the source IP if confirmed malicious
5. Update IDS signatures and rules to improve detection

## Indicators of Compromise (IOCs)
- Source IP: {src_ip}
- Alert Signature: {signature}
- Alert Category: {category}

> ⚠️ *This is an automated fallback analysis. For AI-powered analysis, ensure Ollama is running with the Llama 3 model.*"""

        return analysis
