# מערכת גילוי חדירות

מערכת גילוי חדירות מבוססת Flask ומיועדת לניתוח תעבורת רשת והגנה על מערכות מידע. המערכת כוללת אפשרויות להתחברות, צפייה בסיכומי תנועה, והתראות בזמן אמת על ניסיון חדירה.

## מבנה המערכת

המערכת מורכבת ממספר חלקים עיקריים:

1. **שרת Flask** - שרת ניהול מבוסס Flask לטיפול בבקשות HTTP ולהצגת ממשק המשתמש.
2. **מודולי ניתוח** - כולל פונקציות לזיהוי תקיפות כמו SQL Injection, Directory Traversal ו-Command Injection.
3. **ממשק משתמש** - דפים HTML לצפייה והתראה על התקפות.

## התקנה

1. **התקנת ספריות**

   על מנת להריץ את המערכת, יש להתקין את הספריות הבאות:

   ```bash
   pip install flask scapy
   ```

2. **הגדרת משתני סביבה**

   יש להגדיר את משתנה הסביבה `SECRET_KEY` לפני הרצת השרת. לדוגמה:

   ```bash
   export SECRET_KEY='your_secret_key'
   ```

3. **יצירת תיקיות קבצים**

   ודא שיש לך תיקיית `logs` עבור קבצי הלוגים.

## הפעלת המערכת

להפעלת המערכת, הרץ את הקובץ `main.py`:

```bash
python main.py
```

המערכת תתנהל על פורט 5000 וניתן לגשת אליה בדפדפן בכתובת:

```
http://127.0.0.1:5000
```

## חלקי הקוד

### `main.py`

הקובץ הראשי שמנהל את היישום. כולל ניהול סשן, רוטות לוגין, ותצוגה של התראות וסיכומי תנועה.

### מודולי ניתוח

- **`core/rules.py`** - כולל פונקציות לזיהוי SQL Injection, Directory Traversal ו-Command Injection.
- **`core/alerts.py`** - ניהול התראות עבור ניסי תקיפה.

### קבצי HTML

- **`templates/index.html`** - דף התראות בזמן אמת.
 
- **`templates/login.html`** - דף התחברות.
 
- **`templates/traffic_summary.html`** - דף סיכומי תנועה.


## הוראות שימוש

### התחברות

בעת כניסתך למערכת, תופיע דף התחברות. השתמש בשם המשתמש והסיסמה הבאים:

- **שם משתמש**: `admin`
- **סיסמה**: `admin_password`
<img width="414" alt="image" src="https://github.com/user-attachments/assets/cc817fc7-303b-4faa-a4e3-eca8022fb955">


### דף התראות

לאחר ההתחברות, תועבר לדף התראות בזמן אמת. הדף מציג התראות בזמן אמת שנאספו ממערכת ה-Live Log.
<img width="959" alt="image" src="https://github.com/user-attachments/assets/2c705454-1718-4ac6-b383-40f42d3cf77a">


### דף סיכומי תנועה

דף סיכומי התנועה מציג את סיכומי התעבורה שנאספו מהתעבורה ברשת. תוכל לצפות בסיכומים ולבצע ניתוחים.
<img width="959" alt="image" src="https://github.com/user-attachments/assets/bedaad31-f0c4-43c8-8a9d-b011835763f3">

