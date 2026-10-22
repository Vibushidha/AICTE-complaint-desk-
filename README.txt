AICTE COMPLAINT DESK — ENHANCED SIH PROTOTYPE

Files:
- AICTE_Complaint_Desk_Updated.py : Streamlit application
- requirements.txt                : Python dependencies

Run on Windows:
1. Extract this ZIP into a folder.
2. Open Command Prompt in that folder.
3. Create/activate a virtual environment if desired.
4. Install dependencies:
   python -m pip install -r requirements.txt
5. Start the application:
   streamlit run AICTE_Complaint_Desk_Updated.py

Demo accounts (change/remove before any real deployment):
Administrator: admin / admin123
Bureau Officer: officer / officer123
Complainant: student / student123

Features included in this prototype:
- Complaint submission, tracking by ID, role-based views, activity timeline
- Rules-first categorization, duplicate signals, priority/SLA handling and escalation
- Evidence upload and text extraction; OCR requires Tesseract installed on the machine
- Workload recommendation, root-cause/repeat-issue review, hash-linked audit log
- Assisted complaint draft builder
- Deadline reminder dashboard (computed on page load; not a background scheduler)
- Resolution feedback and quality metrics
- Related-complaint explorer using heuristic text similarity and shared category/institution
- What-if capacity simulator with visible assumptions
- Existing analytics, reports, coordination, risk scorecard and notifications

Important limitations:
- This is a prototype, not a production-ready government service.
- The new relationship explorer is heuristic, not a semantic AI model.
- The what-if simulator is arithmetic scenario planning, not a predictive forecast.
- Email/SMS and unattended reminders need a scheduled worker and configured provider.
- Change the demo credentials, review access control, configure secure deployment, and test all roles before sharing.
- Existing SQLite records are preserved with additive column migrations. Back up the database before upgrading any important deployment.
- Python syntax was checked, but all workflows still need live testing in your environment.
