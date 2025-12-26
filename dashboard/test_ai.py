from ai_analyzer import AIAnalyzer

analyzer = AIAnalyzer()
print("AI Analyzer initialized successfully")

# Test classification
result = analyzer.classify_vulnerability("SQL injection attack")
print(f"Classification test: {result}")