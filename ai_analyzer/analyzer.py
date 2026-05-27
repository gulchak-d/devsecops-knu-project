import os
import sys
import json
from google import genai
from dotenv import load_dotenv

# Завантажує змінні середовища з .env файлу
load_dotenv() 

# 1. Перевіряємо наявність змінної
if not os.environ.get("GEMINI_API_KEY"):
    print("❌ Помилка: Змінна середовища GEMINI_API_KEY не знайдена!")
    sys.exit(1)

# 2. Ініціалізація клієнта
client = genai.Client()

def verify_finding_with_ai(finding):
    """Відправляє знайдену вразливість до ШІ для верифікації"""
    prompt = f"""
    Ти — Senior DevSecOps інженер. Статичний аналізатор (SAST) знайшов таку потенційну вразливість у коді:
    
    Файл: {finding.get('path')}
    Рядок: {finding.get('start', {}).get('line')}
    Опис від сканера: {finding.get('extra', {}).get('message')}
    
    Завдання:
    1. Визнач, чи це реальна загроза (True Positive), чи хибне спрацьовування (False Positive).
    2. Поясни причину.
    3. Якщо це True Positive, напиши виправлений (безпечний) варіант коду.
    
    Почни свою відповідь чітко з фрази "ВЕРДИКТ: True Positive" або "ВЕРДИКТ: False Positive".
    """
    
    try:
        # Виклик моделі за новим синтаксисом (прямо через client)
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        return response.text
    except Exception as e:
        return f"Помилка API: {str(e)}"

def main():
    print("🤖 Запуск AI Security Analyzer...")
    
    report_path = "semgrep_report.json"
    
    if not os.path.exists(report_path):
        print(f"⚠️ Файл {report_path} не знайдено. Пропускаємо аналіз.")
        sys.exit(0)
        
    with open(report_path, "r", encoding="utf-8") as f:
        try:
            report_data = json.load(f)
        except json.JSONDecodeError:
            print("❌ Помилка читання JSON звіту.")
            sys.exit(1)

    findings = report_data.get("results", [])
    if not findings:
        print("✅ Сканер не знайшов вразливостей. Код чистий!")
        sys.exit(0)

    critical_issues_found = False

    for finding in findings:
        print(f"\n🔍 Перевірка файлу {finding.get('path')} (рядок {finding.get('start', {}).get('line')})...")
        
        ai_response = verify_finding_with_ai(finding)
        print("-" * 40)
        print(ai_response)
        print("-" * 40)
        
        # Quality Gate: перевіряємо вердикт ШІ
        if "ВЕРДИКТ: True Positive" in ai_response:
            critical_issues_found = True

    if critical_issues_found:
        print("\n🚨 AI Analyzer підтвердив наявність критичних вразливостей (True Positive)!")
        print("🛑 Пайплайн зупинено. Виправте код і зробіть коміт знову.")
        sys.exit(1)
    else:
        print("\n✅ Всі знахідки визнані як False Positive. Продовжуємо деплой!")
        sys.exit(0)

if __name__ == "__main__":
    main()