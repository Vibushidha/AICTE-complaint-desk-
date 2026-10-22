import os
import re
import json
import sqlite3
import hashlib
import hmac
import secrets
import io
import mimetypes
from pathlib import Path
from datetime import datetime, date, timedelta
from difflib import SequenceMatcher

import pandas as pd
import streamlit as st

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "aicte_complaints.db"
EVIDENCE_DIR = APP_DIR / "evidence_uploads"
EVIDENCE_DIR.mkdir(exist_ok=True)
MAX_UPLOAD_MB = 10

st.set_page_config(page_title="AICTE Complaint Desk", page_icon="🏛️", layout="wide")
BUREAUS = [
    "Approval Bureau", "Policy & Academic Planning Bureau", "Administration Bureau",
    "Finance Bureau", "Research & Institutional Development Cell", "Student Grievance Cell",
    "Other / Needs Review"
]
CATEGORIES = [
    "Approval / Affiliation", "Institution Infrastructure", "Faculty / Staff",
    "Student Welfare", "Examination / Academic", "Fee / Finance", "Scholarship",
    "Discrimination / Harassment", "Other"
]
PRIORITIES = ["Low", "Medium", "High", "Critical"]
STATUSES = ["Submitted", "Under Review", "Assigned", "In Progress", "Awaiting Information", "Resolved", "Closed", "Rejected"]
TERMINAL = {"Resolved", "Closed", "Rejected"}
ROUTE = {
    "Approval / Affiliation": "Approval Bureau",
    "Institution Infrastructure": "Policy & Academic Planning Bureau",
    "Faculty / Staff": "Administration Bureau",
    "Student Welfare": "Student Grievance Cell",
    "Examination / Academic": "Policy & Academic Planning Bureau",
    "Fee / Finance": "Finance Bureau",
    "Scholarship": "Student Grievance Cell",
    "Discrimination / Harassment": "Student Grievance Cell",
    "Other": "Other / Needs Review",
}
SLA_DAYS = {"Critical": 3, "High": 7, "Medium": 14, "Low": 21}

def now_text():
    return datetime.now().isoformat(timespec="minutes")

def connect():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def add_column(con, table, name, definition):
    cols = {r["name"] for r in con.execute(f"PRAGMA table_info({table})")}
    if name not in cols:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")

def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 240000).hex()
    return f"pbkdf2_sha256${salt}${digest}"

def verify_password(stored, supplied):
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, salt, digest = stored.split("$", 2)
            return hmac.compare_digest(password_hash(supplied, salt).split("$", 2)[2], digest)
        except Exception:
            return False
    # One-time compatibility for existing prototype accounts; login upgrades the value.
    return hmac.compare_digest(stored, supplied)

def audit_event(actor, action, tracking_id=None, details=""):
    with connect() as con:
        previous = con.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = previous[0] if previous else "GENESIS"
        timestamp = now_text()
        payload = "|".join([timestamp, str(actor), str(tracking_id or ""), str(action), str(details), prev_hash])
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        con.execute("INSERT INTO audit_log(event_time,actor,tracking_id,action,details,previous_hash,entry_hash) VALUES(?,?,?,?,?,?,?)",
                    (timestamp, actor, tracking_id, action, details, prev_hash, digest))
        con.commit()

def audit_chain_status():
    with connect() as con:
        rows = con.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    previous = "GENESIS"
    for row in rows:
        payload = "|".join([row["event_time"], row["actor"], str(row["tracking_id"] or ""), row["action"], str(row["details"] or ""), previous])
        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if row["previous_hash"] != previous or not hmac.compare_digest(row["entry_hash"], expected):
            return False, len(rows)
        previous = row["entry_hash"]
    return True, len(rows)

def extract_evidence_text(uploaded_file):
    name = uploaded_file.name.lower()
    raw = uploaded_file.getvalue()
    try:
        if name.endswith(".pdf"):
            import fitz
            doc = fitz.open(stream=raw, filetype="pdf")
            text = "\n".join(page.get_text() for page in doc).strip()
            if text:
                return text, "PDF text extracted"
            try:
                import pytesseract
                from PIL import Image
                extracted=[]
                for page in doc:
                    pix = page.get_pixmap(matrix=fitz.Matrix(2,2), alpha=False)
                    image = Image.open(io.BytesIO(pix.tobytes("png")))
                    extracted.append(pytesseract.image_to_string(image))
                text = "\n".join(extracted).strip()
                return text, "OCR completed" if text else "No readable text found"
            except Exception:
                return "", "Scanned PDF detected; install Tesseract + pytesseract for OCR"
        if name.endswith((".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp")):
            from PIL import Image
            import pytesseract
            text = pytesseract.image_to_string(Image.open(io.BytesIO(raw))).strip()
            return text, "OCR completed" if text else "No readable text found"
        if name.endswith((".txt", ".csv")):
            return raw.decode("utf-8", errors="ignore")[:100000], "Text extracted"
    except ImportError:
        return "", "OCR dependency missing; install pymupdf, pillow and pytesseract"
    except Exception as exc:
        return "", f"Could not extract text: {type(exc).__name__}"
    return "", "File stored; automatic extraction is not supported for this format"

def evidence_panel(user, df):
    st.subheader("Evidence & document intelligence")
    st.caption("Upload supporting documents, extract readable text where possible, and review evidence linked to a complaint.")
    if df.empty:
        st.info("No cases are available to this account yet.")
        return
    allowed = df.copy()
    if user["role"] != "Administrator":
        allowed = allowed[allowed.apply(lambda r: can_view_case(r, user), axis=1)]
    if allowed.empty:
        st.info("No cases are available for evidence access.")
        return
    tracking = st.selectbox("Link evidence to complaint", allowed["tracking_id"].tolist(), format_func=lambda x:fmt_case_label(allowed,x), key="evidence_case")
    selected = allowed[allowed["tracking_id"] == tracking].iloc[0]
    if selected.get("is_confidential") and user["role"] != "Administrator" and selected.get("assigned_to") != user["username"] and selected.get("complainant") != user["username"]:
        st.error("Access to this confidential case is restricted.")
        return
    files = st.file_uploader("Choose evidence files", type=["pdf","png","jpg","jpeg","webp","txt","csv"], accept_multiple_files=True, help=f"Maximum {MAX_UPLOAD_MB} MB per file. Avoid uploading unnecessary personal data.")
    if st.button("Save evidence and extract text", type="primary", disabled=not files):
        saved = 0
        for f in files:
            if f.size > MAX_UPLOAD_MB * 1024 * 1024:
                st.warning(f"Skipped {f.name}: exceeds {MAX_UPLOAD_MB} MB.")
                continue
            raw = f.getvalue()
            stored = secrets.token_hex(16) + Path(f.name).suffix.lower()
            target = EVIDENCE_DIR / stored
            target.write_bytes(raw)
            extracted, status = extract_evidence_text(f)
            with connect() as con:
                con.execute("INSERT INTO evidence(tracking_id,original_name,stored_name,mime_type,file_size,extracted_text,uploaded_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                            (tracking, Path(f.name).name, stored, f.type or mimetypes.guess_type(f.name)[0], len(raw), extracted, user["username"], now_text()))
                con.commit()
            log_activity(tracking, user["username"], "Evidence uploaded", f"{Path(f.name).name}: {status}")
            audit_event(user["username"], "Evidence uploaded", tracking, f"{Path(f.name).name} ({len(raw)} bytes)")
            st.write(f"**{f.name}** — {status}")
            if extracted:
                with st.expander(f"Extracted text preview: {f.name}"):
                    st.text(extracted[:5000])
            saved += 1
        if saved:
            st.success(f"Saved {saved} evidence file(s).")
            st.rerun()
    with connect() as con:
        rows = con.execute("SELECT * FROM evidence WHERE tracking_id=? ORDER BY created_at DESC", (tracking,)).fetchall()
    st.markdown("#### Existing evidence")
    if not rows:
        st.info("No evidence has been uploaded for this complaint.")
    for row in rows:
        with st.expander(f"{row['original_name']} · {row['created_at']} · {row['file_size'] or 0:,} bytes"):
            st.caption(f"Uploaded by {row['uploaded_by']} · {row['mime_type'] or 'unknown type'}")
            path = EVIDENCE_DIR / row["stored_name"]
            if path.exists():
                st.download_button("Download original file", path.read_bytes(), file_name=row["original_name"], mime=row["mime_type"] or "application/octet-stream", key=f"ev_dl_{row['id']}")
            if row["extracted_text"]:
                st.text_area("Extracted text", row["extracted_text"], height=160, key=f"ev_text_{row['id']}")
            else:
                st.warning("No text was extracted. Check readability or install the optional OCR dependencies.")

def workload_panel(df):
    st.subheader("Smart workload distribution")
    st.caption("Recommendations are advisory; an administrator must confirm assignments.")
    with connect() as con:
        officers = pd.read_sql_query("SELECT username,full_name,bureau FROM users WHERE role='Bureau Officer'", con)
    if officers.empty:
        st.info("No bureau-officer accounts exist yet.")
        return
    open_cases = df[~df["status"].isin(TERMINAL)] if not df.empty else df
    rows=[]
    for _, officer in officers.iterrows():
        subset = open_cases[(open_cases["assigned_to"] == officer["username"]) | ((open_cases["bureau"] == officer["bureau"]) & (open_cases["assigned_to"].isna()))] if not open_cases.empty else open_cases
        rows.append({"Username":officer["username"],"Officer":officer["full_name"],"Bureau":officer["bureau"],"Assigned open cases":int((open_cases["assigned_to"] == officer["username"]).sum()) if not open_cases.empty else 0,"Overdue assigned":int(sum(is_overdue(r) for _,r in open_cases[open_cases["assigned_to"] == officer["username"]].iterrows())) if not open_cases.empty else 0})
    table=pd.DataFrame(rows).sort_values(["Overdue assigned","Assigned open cases"])
    st.dataframe(table, hide_index=True, use_container_width=True)
    unassigned = open_cases[open_cases["assigned_to"].isna() | open_cases["assigned_to"].fillna("").eq("")] if not open_cases.empty else open_cases
    if not unassigned.empty:
        case_id=st.selectbox("Unassigned case", unassigned["tracking_id"].tolist(), format_func=lambda x:fmt_case_label(unassigned,x), key="workload_case")
        case=unassigned[unassigned["tracking_id"]==case_id].iloc[0]
        eligible=officers[(officers["bureau"]==case["bureau"]) | officers["bureau"].eq("All Bureaus")]
        if eligible.empty:
            st.warning(f"No officer account matches {case['bureau']}. Add an officer account for this bureau before assigning.")
        else:
            scored=[]
            for _,o in eligible.iterrows():
                assigned_count=int((open_cases["assigned_to"]==o["username"]).sum())
                overdue_count=sum(is_overdue(r) for _,r in open_cases[open_cases["assigned_to"]==o["username"]].iterrows())
                scored.append((overdue_count,assigned_count,o["username"],o["full_name"]))
            scored.sort()
            chosen=scored[0]
            st.info(f"Suggested officer: **{chosen[3]} (@{chosen[2]})** — {chosen[1]} assigned open case(s), {chosen[0]} overdue.")
            if st.button("Assign to suggested officer", type="primary"):
                with connect() as con:
                    con.execute("UPDATE complaints SET assigned_to=?,status=CASE WHEN status='Submitted' THEN 'Assigned' ELSE status END,updated_at=? WHERE tracking_id=?",(chosen[2],now_text(),case_id))
                    con.commit()
                log_activity(case_id,"admin","Workload-based assignment",f"Assigned to {chosen[2]} by recommendation; admin confirmed.")
                audit_event("admin","Workload-based assignment",case_id,f"Assigned to {chosen[2]}")
                notify(chosen[2],case_id,"Complaint assigned to you",f"{case_id} was assigned to you by an administrator.")
                st.success("Assignment saved.")
                st.rerun()

def root_cause_panel(df):
    st.subheader("Root-cause & repeat-issue analysis")
    st.caption("Pattern signals are based on complaint text/category and are prompts for human review, not proof of institutional fault.")
    if df.empty:
        st.info("No complaint records to analyze.")
        return
    left,right=st.columns(2)
    with left:
        st.markdown("#### Repeated categories")
        st.dataframe(df.groupby("category",dropna=False).size().sort_values(ascending=False).rename("Cases").reset_index(),hide_index=True,use_container_width=True)
    with right:
        st.markdown("#### Institutions with recurring cases")
        repeats=df.groupby(["institution","category"],dropna=False).size().reset_index(name="Cases")
        repeats=repeats[repeats["Cases"]>=2].sort_values("Cases",ascending=False)
        if repeats.empty: st.info("No repeated institution/category pattern found in the visible cases.")
        else: st.dataframe(repeats,hide_index=True,use_container_width=True)
    st.markdown("#### Suggested review prompts")
    if "institution" in df:
        repeats=df.groupby(["institution","category"],dropna=False).size().reset_index(name="Cases")
        repeats=repeats[repeats["Cases"]>=2]
        for _,r in repeats.head(8).iterrows():
            st.warning(f"{r['Cases']} cases tagged **{r['category']}** at **{r['institution']}**. Review whether a shared process issue or preventive action is appropriate.")

def audit_panel():
    st.subheader("Tamper-evident audit log")
    ok,count=audit_chain_status()
    if ok: st.success(f"Hash-chain verification passed · {count} audit event(s) checked")
    else: st.error(f"Hash-chain verification failed · inspect audit records ({count} total)")
    with connect() as con:
        rows=pd.read_sql_query("SELECT id,event_time,actor,tracking_id,action,details,previous_hash,entry_hash FROM audit_log ORDER BY id DESC LIMIT 500",con)
    if rows.empty: st.info("No audit events recorded yet.")
    else:
        q=st.text_input("Filter audit events",key="audit_filter")
        if q:
            rows=rows[rows.astype(str).apply(lambda c:c.str.contains(q,case=False,regex=False)).any(axis=1)]
        st.dataframe(rows,hide_index=True,use_container_width=True)


def filing_assistant_panel():
    st.subheader("Assisted complaint filing")
    st.caption("Answer a few prompts to prepare a clearer complaint draft. Review all details before submitting it through Submit Complaint.")
    language = st.selectbox("Draft language", ["English", "தமிழ்", "हिन्दी"], key="assist_language")
    institution = st.text_input("Institution name", key="assist_institution")
    issue = st.selectbox("What is the main issue?", CATEGORIES, key="assist_category")
    when = st.text_input("When did it happen? (approximate date is fine)", key="assist_when")
    previous = st.selectbox("Have you already contacted the institution?", ["Not yet", "Yes, no response", "Yes, response received"], key="assist_previous")
    facts = st.text_area("Describe what happened in your own words", height=150, key="assist_facts")
    impact = st.text_area("How did this affect you or other students?", height=90, key="assist_impact")
    evidence = st.text_input("Evidence available (optional)", key="assist_evidence", placeholder="e.g. receipt, email, notice")
    if st.button("Prepare complaint draft", type="primary", key="assist_make_draft"):
        if not institution.strip() or not facts.strip():
            st.error("Please provide the institution name and a description of the issue.")
        else:
            draft = (f"Issue category: {issue}\nInstitution: {institution.strip()}\nWhen it happened: {when.strip() or 'Not specified'}\n"
                     f"Previous contact: {previous}\n\nWhat happened:\n{facts.strip()}\n\nImpact:\n{impact.strip() or 'Not specified'}\n\n"
                     f"Evidence available: {evidence.strip() or 'Not specified'}")
            st.session_state["assisted_complaint_draft"] = draft
    if st.session_state.get("assisted_complaint_draft"):
        st.text_area("Review and edit your draft", value=st.session_state["assisted_complaint_draft"], height=240, key="assist_review")
        st.download_button("Download draft", st.session_state["assisted_complaint_draft"].encode("utf-8"), "complaint_draft.txt", "text/plain")
        st.info("This assistant organizes your description; it does not verify allegations or submit a complaint automatically. Submit the reviewed information using the Submit Complaint tab.")

def resolution_quality_panel(df):
    st.subheader("Resolution quality & reopening analysis")
    if df.empty:
        st.info("No complaint records available."); return
    closed = df[df["status"].isin(["Resolved", "Closed"])]
    total = len(df)
    resolved_rate = 100 * len(closed) / total if total else 0
    reopened = int(pd.to_numeric(df.get("reopened_count", pd.Series(0, index=df.index)), errors="coerce").fillna(0).sum())
    transfers = int(pd.to_numeric(df.get("transfer_count", pd.Series(0, index=df.index)), errors="coerce").fillna(0).sum())
    feedback = pd.to_numeric(closed.get("satisfaction_score", pd.Series(dtype=float)), errors="coerce").dropna()
    a,b,c,d=st.columns(4); a.metric("Resolved / closed", f"{resolved_rate:.1f}%"); b.metric("Reopen events", reopened); c.metric("Transfer events", transfers); d.metric("Avg. satisfaction", f"{feedback.mean():.1f}/5" if not feedback.empty else "No ratings")
    st.caption("Reopen and transfer counters start at zero for older records and only become meaningful when those workflows are used. Do not treat closure rate alone as resolution quality.")
    if not closed.empty:
        st.markdown("#### Closed cases awaiting feedback")
        cols=[c for c in ["tracking_id","title","institution","status","updated_at","satisfaction_score"] if c in closed.columns]
        st.dataframe(closed[cols], hide_index=True, use_container_width=True)

def relationship_graph_panel(df):
    st.subheader("Complaint relationship explorer")
    st.caption("Find candidate related complaints by shared institution/category and similar wording. Matches are investigation leads, not proof that cases have the same cause.")
    if df.empty or len(df)<2:
        st.info("At least two visible complaints are needed."); return
    threshold=st.slider("Text similarity threshold", 30, 90, 55, 5, key="relationship_threshold")
    rows=[]
    records=df.fillna("").to_dict("records")
    for i in range(len(records)):
        for j in range(i+1,len(records)):
            x,y=records[i],records[j]
            same_inst=bool(x.get("institution")) and str(x.get("institution")).strip().casefold()==str(y.get("institution")).strip().casefold()
            same_cat=bool(x.get("category")) and x.get("category")==y.get("category")
            text_a=f"{x.get('title','')} {x.get('description','')}".lower()
            text_b=f"{y.get('title','')} {y.get('description','')}".lower()
            sim=SequenceMatcher(None, normalize(text_a), normalize(text_b)).ratio()*100
            if (same_inst and same_cat) or sim>=threshold:
                rows.append({"Complaint A":x.get("tracking_id"),"Complaint B":y.get("tracking_id"),"Same institution":same_inst,"Same category":same_cat,"Text similarity %":round(sim,1),"Review basis":"Same institution + category" if same_inst and same_cat else "Text similarity"})
    if rows:
        st.dataframe(pd.DataFrame(rows).sort_values("Text similarity %",ascending=False),hide_index=True,use_container_width=True)
    else: st.info("No likely links found at this threshold.")

def policy_simulator_panel(df):
    st.subheader("What-if workload & SLA simulator")
    st.caption("A simple scenario model for planning only. It does not predict outcomes with certainty or change real assignments.")
    open_cases = df[~df["status"].isin(TERMINAL)] if not df.empty else df
    overdue_now = sum(is_overdue(r) for _,r in open_cases.iterrows()) if not open_cases.empty else 0
    left,right=st.columns(2)
    with left:
        extra_officers=st.slider("Additional officers",0,20,2,key="sim_officers")
        weekly_capacity=st.slider("Cases one officer can process per week",1,30,5,key="sim_capacity")
    with right:
        incoming=st.slider("Expected new cases per week",0,200,20,key="sim_incoming")
        weeks=st.slider("Planning horizon (weeks)",1,12,4,key="sim_weeks")
    with connect() as con:
        officer_count=con.execute("SELECT COUNT(*) FROM users WHERE role='Bureau Officer'").fetchone()[0]
    total_officers=max(1,officer_count+extra_officers)
    capacity=total_officers*weekly_capacity*weeks
    incoming_total=incoming*weeks
    workload=len(open_cases)+incoming_total
    projected_backlog=max(0,workload-capacity)
    a,b,c=st.columns(3); a.metric("Current open cases",len(open_cases)); b.metric("Estimated capacity",capacity); c.metric("Illustrative remaining backlog",projected_backlog)
    st.write(f"Current overdue cases: **{overdue_now}**. Scenario assumes {incoming_total} incoming cases and a steady processing rate of {weekly_capacity} cases per officer per week.")
    st.warning("This is a transparent arithmetic scenario, not an AI forecast. Actual demand, case complexity, leave, and bureau-specific skills are not modeled.")

def notifications_reminder_panel(df):
    st.subheader("Deadline & follow-up reminders")
    if df.empty:
        st.info("No visible complaints."); return
    today=date.today(); soon=[]; overdue=[]
    for _,row in df.iterrows():
        if row.get("status") in TERMINAL or not row.get("due_date"): continue
        try: due=date.fromisoformat(str(row["due_date"])[:10])
        except Exception: continue
        item={"Tracking ID":row.get("tracking_id"),"Title":row.get("title"),"Bureau":row.get("bureau"),"Assigned to":row.get("assigned_to"),"Due date":str(due),"Days remaining":(due-today).days}
        if due<today: overdue.append(item)
        elif (due-today).days<=3: soon.append(item)
    a,b=st.columns(2); a.metric("Overdue open cases",len(overdue)); b.metric("Due within 3 days",len(soon))
    if overdue:
        st.markdown("#### Overdue"); st.dataframe(pd.DataFrame(overdue),hide_index=True,use_container_width=True)
    if soon:
        st.markdown("#### Due soon"); st.dataframe(pd.DataFrame(soon),hide_index=True,use_container_width=True)
    if not overdue and not soon: st.success("No visible cases are overdue or due within the next three days.")
    st.caption("These reminders are calculated when the dashboard is opened. For unattended email/SMS reminders, deploy a scheduled background job and configure a provider.")


def init_db():
    with connect() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT NOT NULL,
            full_name TEXT NOT NULL, bureau TEXT)""")
        con.execute("""CREATE TABLE IF NOT EXISTS complaints(
            id INTEGER PRIMARY KEY AUTOINCREMENT, tracking_id TEXT UNIQUE,
            title TEXT NOT NULL, description TEXT NOT NULL, institution TEXT NOT NULL,
            institution_type TEXT, state TEXT, category TEXT NOT NULL, priority TEXT NOT NULL,
            status TEXT NOT NULL, bureau TEXT, assigned_to TEXT, complainant TEXT NOT NULL,
            complainant_email TEXT, submitted_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            due_date TEXT, resolution TEXT, is_confidential INTEGER DEFAULT 0)""")
        con.execute("""CREATE TABLE IF NOT EXISTS activity(
            id INTEGER PRIMARY KEY AUTOINCREMENT, tracking_id TEXT NOT NULL, actor TEXT NOT NULL,
            action TEXT NOT NULL, note TEXT, created_at TEXT NOT NULL)""")
        # Additive migrations preserve existing v1/v2 complaint records.
        migrations = [
            ("ai_category", "TEXT"), ("ai_bureau", "TEXT"), ("ai_explanation", "TEXT"),
            ("duplicate_of", "TEXT"), ("duplicate_score", "REAL"),
            ("escalation_level", "INTEGER DEFAULT 0"), ("escalated_at", "TEXT"),
            ("group_id", "TEXT"), ("confidential_note", "TEXT"),
            ("original_language", "TEXT DEFAULT 'English'"), ("english_translation", "TEXT"),
            ("translation_status", "TEXT DEFAULT 'Not required'"),
            ("reopened_count", "INTEGER DEFAULT 0"), ("transfer_count", "INTEGER DEFAULT 0"),
            ("satisfaction_score", "INTEGER"), ("resolution_feedback", "TEXT")
        ]
        for col, definition in migrations:
            add_column(con, "complaints", col, definition)
        con.execute("""CREATE TABLE IF NOT EXISTS notifications(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, tracking_id TEXT,
            title TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL,
            is_read INTEGER DEFAULT 0)""")
        con.execute("""CREATE TABLE IF NOT EXISTS bureau_requests(
            id INTEGER PRIMARY KEY AUTOINCREMENT, tracking_id TEXT NOT NULL,
            requesting_bureau TEXT NOT NULL, target_bureau TEXT NOT NULL,
            requested_by TEXT NOT NULL, request_note TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending', response_note TEXT,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS evidence(
            id INTEGER PRIMARY KEY AUTOINCREMENT, tracking_id TEXT NOT NULL, original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL, mime_type TEXT, file_size INTEGER, extracted_text TEXT,
            uploaded_by TEXT NOT NULL, created_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS audit_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_time TEXT NOT NULL, actor TEXT NOT NULL,
            tracking_id TEXT, action TEXT NOT NULL, details TEXT, previous_hash TEXT, entry_hash TEXT NOT NULL)""")
        if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            con.executemany("INSERT INTO users VALUES(?,?,?,?,?)", [
                ("admin", "admin123", "Administrator", "System Administrator", "All Bureaus"),
                ("officer", "officer123", "Bureau Officer", "Demo Bureau Officer", "Student Grievance Cell"),
                ("student", "student123", "Complainant", "Demo Complainant", None)])
        con.commit()


def seed_demo_data():
    """Add a set of fictional demonstration complaints once, without changing real records."""
    with connect() as con:
        count = con.execute(
            "SELECT COUNT(*) FROM complaints WHERE tracking_id LIKE 'DEMO-2026-%'"
        ).fetchone()[0]
        if count:
            return False, count

        today = date.today()
        samples = [
            ("001","Scholarship disbursement delay","Several students report that their semester scholarship has not been credited.","Demo Institute of Technology","Tamil Nadu","Scholarship","High","In Progress","Student Grievance Cell","officer",9,2,0,"Fictional sample: bureau is checking the release timeline."),
            ("002","Hostel drinking water concern","Students report irregular access to safe drinking water in one hostel block.","Fictional Green Valley College","Karnataka","Institution Infrastructure","Critical","Under Review","Policy & Academic Planning Bureau","admin",5,-2,0,"Fictional sample: inspection request prepared."),
            ("003","Examination result correction","Internal marks appear incorrectly in the published result, according to the complainant.","Demo Institute of Science","Kerala","Examination / Academic","Medium","Assigned","Policy & Academic Planning Bureau","admin",4,10,0,"Fictional sample: awaiting supporting documents."),
            ("004","Fee refund pending","A student reports that a fee refund has not been processed after withdrawal.","Sample National College","Maharashtra","Fee / Finance","High","Awaiting Information","Finance Bureau","admin",12,-5,0,"Fictional sample: payment reference requested."),
            ("005","Faculty vacancy information mismatch","Public faculty vacancy details appear inconsistent with the latest institution submission.","Fictional Riverbank Engineering College","Andhra Pradesh","Faculty / Staff","Medium","In Progress","Administration Bureau","admin",6,5,0,"Fictional sample: bureau reviewing submitted records."),
            ("006","Accessibility support request","A student requests improved wheelchair access to classrooms in the academic block.","Demo Inclusive Engineering Institute","Tamil Nadu","Student Welfare","Medium","Submitted","Student Grievance Cell",None,2,12,0,"Fictional sample: awaiting assignment."),
            ("007","Approval status clarification","An institution requests clarification about the status of an approval-related application.","Sample Horizon Technical College","Telangana","Approval / Affiliation","Low","Resolved","Approval Bureau","admin",25,0,0,"Fictional sample: clarification shared with institution."),
            ("008","Laboratory electrical safety issue","A safety concern is reported about damaged electrical fittings in a teaching laboratory.","Fictional Sunrise Institute","Rajasthan","Institution Infrastructure","Critical","In Progress","Policy & Academic Planning Bureau","admin",8,-3,0,"Fictional sample: overdue case requiring escalation."),
            ("009","Research stipend status","Research students request an update on the expected stipend release timeline.","Demo Research and Technology College","Delhi","Scholarship","Medium","Under Review","Student Grievance Cell","officer",3,1,0,"Fictional sample: related scholarship concern."),
            ("010","Confidential student welfare report","A student requests confidential review of a student welfare concern.","Fictional Eastview College","Tamil Nadu","Discrimination / Harassment","Critical","Under Review","Student Grievance Cell","officer",2,4,1,"Fictional confidential example; contains no real personal information."),
            ("011","Institution affiliation details update","An institution requests correction of its displayed affiliation details.","Demo Coastal Polytechnic","Goa","Approval / Affiliation","Low","Closed","Approval Bureau","admin",35,0,0,"Fictional sample: correction confirmed."),
            ("012","Possible duplicate scholarship delay","Students at the same fictional institution report delayed scholarship credit for the current term.","Demo Institute of Technology","Tamil Nadu","Scholarship","High","Submitted","Student Grievance Cell",None,1,8,0,"Fictional sample: review whether related to DEMO-2026-001."),
        ]
        for code,title,description,institution,state,category,priority,status,bureau,assignee,age,due_offset,confidential,resolution in samples:
            tracking = f"DEMO-2026-{code}"
            submitted = (datetime.now().replace(hour=10, minute=15, second=0, microsecond=0) - timedelta(days=age)).isoformat(timespec="minutes")
            updated = (datetime.now().replace(hour=14, minute=20, second=0, microsecond=0) - timedelta(days=max(0, age-1))).isoformat(timespec="minutes")
            due = (today + timedelta(days=due_offset)).isoformat()
            group_id = "DEMO-GRP-SCHOLARSHIP" if code in ("001","009","012") else None
            con.execute("""INSERT INTO complaints
                (tracking_id,title,description,institution,institution_type,state,category,priority,status,bureau,assigned_to,
                 complainant,complainant_email,submitted_at,updated_at,due_date,resolution,is_confidential,ai_category,ai_bureau,
                 ai_explanation,duplicate_of,duplicate_score,escalation_level,escalated_at,group_id,confidential_note)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (tracking,title,description,institution,"Engineering / Technical Institution",state,category,priority,status,bureau,assignee,
                 "student","demo.student@example.invalid",submitted,updated,due,
                 resolution if status in ("Resolved","Closed") else None,confidential,category,bureau,
                 "DEMO DATA — rules-first sample classification","DEMO-2026-001" if code=="012" else None,
                 0.62 if code=="012" else None,1 if due_offset < 0 and status not in TERMINAL else 0,
                 updated if due_offset < 0 and status not in TERMINAL else None,group_id,
                 "Fictional confidential example; not a real report." if confidential else None))
            con.execute("INSERT INTO activity(tracking_id,actor,action,note,created_at) VALUES(?,?,?,?,?)",
                        (tracking,"Demo Seeder","Sample complaint created","Fictional data for prototype demonstration only.",submitted))
            if status != "Submitted":
                con.execute("INSERT INTO activity(tracking_id,actor,action,note,created_at) VALUES(?,?,?,?,?)",
                            (tracking,"Demo Officer","Status updated",f"Fictional demonstration status: {status}",updated))
            if assignee:
                con.execute("INSERT INTO notifications(username,tracking_id,title,message,created_at,is_read) VALUES(?,?,?,?,?,0)",
                            (assignee,tracking,"Demo case assigned",f"{tracking}: {title} — fictional demo record.",updated))
        con.execute("""INSERT INTO bureau_requests
            (tracking_id,requesting_bureau,target_bureau,requested_by,request_note,status,response_note,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            ("DEMO-2026-001","Student Grievance Cell","Finance Bureau","officer",
             "Please verify the scholarship release timeline for this fictional case.","Pending",None,now_text(),now_text()))
        con.execute("""INSERT INTO bureau_requests
            (tracking_id,requesting_bureau,target_bureau,requested_by,request_note,status,response_note,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            ("DEMO-2026-003","Policy & Academic Planning Bureau","Administration Bureau","admin",
             "Please confirm the relevant academic record for this fictional case.","Responded",
             "Demo response: record verification is in progress.",now_text(),now_text()))
        con.commit()
    return True, len(samples)

def log_activity(tracking_id, actor, action, note=""):
    with connect() as con:
        con.execute("INSERT INTO activity(tracking_id,actor,action,note,created_at) VALUES(?,?,?,?,?)",
                    (tracking_id, actor, action, note, now_text()))
        con.commit()
    audit_event(actor, action, tracking_id, note or "")

def notify(username, tracking_id, title, message):
    if not username:
        return
    with connect() as con:
        con.execute("INSERT INTO notifications(username,tracking_id,title,message,created_at) VALUES(?,?,?,?,?)",
                    (username, tracking_id, title, message, now_text()))
        con.commit()

def get_user(username):
    with connect() as con:
        return con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

def all_complaints():
    with connect() as con:
        return pd.read_sql_query("SELECT * FROM complaints ORDER BY submitted_at DESC", con)

def all_activity(tracking):
    with connect() as con:
        return con.execute("SELECT * FROM activity WHERE tracking_id=? ORDER BY created_at DESC", (tracking,)).fetchall()

def visible_cases(df, user):
    if user["role"] == "Administrator":
        return df.copy()
    if user["role"] == "Bureau Officer":
        return df[(df["bureau"] == user.get("bureau")) | (df["assigned_to"] == user["username"])].copy()
    return df[df["complainant"] == user["username"]].copy()

def can_view_case(row, user):
    if user["role"] == "Administrator":
        return True
    if user["role"] == "Bureau Officer":
        in_scope = row["bureau"] == user.get("bureau") or row["assigned_to"] == user["username"]
        return bool(in_scope and (not row.get("is_confidential") or row["assigned_to"] == user["username"]))
    return row["complainant"] == user["username"]

def normalize(s):
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9\s]", " ", str(s or "").lower())).strip()

RULES = {
    "Approval / Affiliation": ["approval", "affiliation", "accreditation", "recognition", "intake", "eoa"],
    "Institution Infrastructure": ["hostel", "building", "laboratory", "sanitation", "water", "infrastructure", "safety"],
    "Faculty / Staff": ["faculty", "teacher", "professor", "staff", "recruitment", "vacancy", "salary delay"],
    "Student Welfare": ["student welfare", "ragging", "counselling", "wellbeing", "student support"],
    "Examination / Academic": ["exam", "examination", "curriculum", "syllabus", "marks", "attendance", "academic"],
    "Fee / Finance": ["fee", "fees", "refund", "payment", "finance", "collection", "tuition", "overcharging"],
    "Scholarship": ["scholarship", "stipend", "financial aid", "grant"],
    "Discrimination / Harassment": ["harassment", "discrimination", "bullying", "abuse", "retaliation"],
}

def classify_rules(title, description, institution):
    text = normalize(f"{title} {description} {institution}")
    scored = {}
    hits = {}
    for cat, terms in RULES.items():
        found = [term for term in terms if normalize(term) in text]
        if found:
            scored[cat] = sum(2 if " " in term else 1 for term in found)
            hits[cat] = found
    if not scored:
        return {"category":"Other", "bureau":ROUTE["Other"], "confidence":0.35,
                "explanation":"No strong keyword match; manual review recommended.", "method":"Rules-first"}
    cat = max(scored, key=scored.get)
    conf = min(.94, .52 + scored[cat] / max(1, sum(scored.values())) * .38)
    return {"category":cat, "bureau":ROUTE[cat], "confidence":round(conf,2),
            "explanation":"Keyword rules matched: " + ", ".join(hits[cat][:5]), "method":"Rules-first"}

def duplicate_matches(title, description, institution, exclude=None):
    df = all_complaints()
    a = normalize(title + " " + description)
    at = normalize(title); ai = normalize(institution)
    found = []
    for _, r in df.iterrows():
        if r["tracking_id"] == exclude:
            continue
        b = normalize(str(r["title"]) + " " + str(r["description"]))
        bt = normalize(r["title"]); bi = normalize(r["institution"])
        seq = SequenceMatcher(None, a, b).ratio()
        title_sim = SequenceMatcher(None, at, bt).ratio()
        inst_sim = SequenceMatcher(None, ai, bi).ratio() if ai and bi else 0
        ta, tb = set(a.split()), set(b.split())
        overlap = len(ta & tb) / max(1, len(ta | tb))
        score = round(.35*seq + .35*title_sim + .20*overlap + .10*inst_sim, 3)
        if score >= .22:
            found.append({"tracking_id":r["tracking_id"], "title":r["title"], "institution":r["institution"],
                          "status":r["status"], "score":score})
    return sorted(found, key=lambda x:x["score"], reverse=True)[:5]

def is_overdue(row):
    if row["status"] in TERMINAL or not row["due_date"]:
        return False
    try:
        return date.fromisoformat(str(row["due_date"])[:10]) < date.today()
    except ValueError:
        return False

def run_sla_sweep():
    """Idempotent daily-on-open escalation: flag overdue cases and notify the assigned officer/admin."""
    df = all_complaints()
    for _, r in df.iterrows():
        if is_overdue(r):
            level = int(r.get("escalation_level") or 0)
            overdue_days = 0
            try:
                overdue_days = (date.today() - date.fromisoformat(str(r["due_date"])[:10])).days
            except ValueError:
                pass
            target_level = 1 if overdue_days >= 0 else 0
            if overdue_days >= 7: target_level = 2
            if overdue_days >= 14: target_level = 3
            if target_level > level:
                with connect() as con:
                    con.execute("UPDATE complaints SET escalation_level=?, escalated_at=?, updated_at=? WHERE tracking_id=?",
                                (target_level, now_text(), now_text(), r["tracking_id"]))
                    con.commit()
                label = {1:"assigned officer reminder",2:"bureau-head escalation",3:"administrator review"}[target_level]
                log_activity(r["tracking_id"], "System", f"SLA escalation level {target_level}",
                             f"{overdue_days} day(s) overdue; {label}.")
                notify(r["assigned_to"], r["tracking_id"], f"SLA escalation level {target_level}",
                       f"{r['tracking_id']} is {overdue_days} day(s) overdue. Escalation: {label}.")
                notify("admin", r["tracking_id"], f"SLA escalation level {target_level}",
                       f"{r['tracking_id']} is {overdue_days} day(s) overdue. Escalation: {label}.")
                if target_level >= 2:
                    with connect() as con:
                        bureau_users=con.execute("SELECT username FROM users WHERE role='Bureau Officer' AND bureau=?",(r["bureau"],)).fetchall()
                    for bu in bureau_users:
                        notify(bu["username"],r["tracking_id"],f"SLA escalation level {target_level}",f"{r['tracking_id']} in {r['bureau']} is {overdue_days} day(s) overdue.")
        elif r["status"] not in TERMINAL and r["due_date"]:
            try:
                days_left = (date.fromisoformat(str(r["due_date"])[:10]) - date.today()).days
                if days_left in (0, 1):
                    # Avoid flooding: one reminder per case/day per recipient.
                    with connect() as con:
                        exists = con.execute("SELECT 1 FROM notifications WHERE tracking_id=? AND title='SLA deadline approaching' AND date(created_at)=date('now','localtime') LIMIT 1",
                                             (r["tracking_id"],)).fetchone()
                    if not exists:
                        msg = f"{r['tracking_id']} is due on {r['due_date']} ({days_left} day(s) remaining)."
                        notify(r["assigned_to"], r["tracking_id"], "SLA deadline approaching", msg)
                        notify("admin", r["tracking_id"], "SLA deadline approaching", msg)
            except ValueError:
                pass

def fmt_case_label(df, tracking):
    rows = df[df["tracking_id"] == tracking]
    return f"{tracking} — {rows.iloc[0]['title']}" if not rows.empty else tracking

def render_table(df):
    if df.empty:
        st.info("No records to show.")
        return
    cols = [c for c in ["tracking_id","title","institution","category","priority","status","bureau","assigned_to","submitted_at","due_date","escalation_level","group_id"] if c in df.columns]
    show = df[cols].copy()
    show.columns = [c.replace("_"," ").title() for c in cols]
    st.dataframe(show, use_container_width=True, hide_index=True)

def notification_panel(user):
    with connect() as con:
        rows = con.execute("SELECT * FROM notifications WHERE username=? ORDER BY created_at DESC LIMIT 50", (user["username"],)).fetchall()
    unread = [r for r in rows if not r["is_read"]]
    st.caption(f"{len(unread)} unread notification(s)")
    if not rows:
        st.info("No notifications yet.")
        return
    for n in rows:
        with st.container(border=True):
            st.markdown(f"**{n['title']}** {'🔵' if not n['is_read'] else ''}")
            st.write(n["message"])
            st.caption(f"{n['created_at']} · {n['tracking_id'] or 'General'}")
            if not n["is_read"] and st.button("Mark as read", key=f"read_{n['id']}"):
                with connect() as con:
                    con.execute("UPDATE notifications SET is_read=1 WHERE id=? AND username=?", (n["id"], user["username"]))
                    con.commit()
                st.rerun()

def track_case(user, df):
    st.subheader("Track a complaint")
    tracking = st.text_input("Tracking ID", key="tracking_lookup", placeholder="AICTE-YYYYMM-12345")
    if st.button("Find complaint", type="primary", key="lookup_button"):
        st.session_state["selected_tracking"] = tracking.strip()
    tracking = st.session_state.get("selected_tracking", "")
    if not tracking:
        return
    with connect() as con:
        row = con.execute("SELECT * FROM complaints WHERE tracking_id=?", (tracking,)).fetchone()
    if not row:
        st.warning("No complaint found for this tracking ID.")
        return
    case = dict(row)
    if not can_view_case(case, user):
        st.error("You do not have permission to view this complaint.")
        return
    st.metric("Status", case["status"])
    st.write(f"**{case['title']}**")
    st.write(f"Institution: {case['institution']} · Category: {case['category']} · Priority: {case['priority']}")
    st.write(f"Bureau: {case['bureau']} · Due date: {case['due_date'] or 'Not set'}")
    if is_overdue(case):
        st.error("This case is overdue.")
    st.write(case["description"])
    if user["role"] != "Complainant" and case.get("english_translation"):
        with st.expander("English translation (review before acting)"):
            st.write(case["english_translation"])
            st.caption("Language: " + str(case.get("original_language") or "Unknown") + " · " + str(case.get("translation_status") or "Translation status unknown"))
    elif user["role"] != "Complainant" and case.get("translation_status") and case.get("original_language") not in (None, "English"):
        st.warning("Complaint language: " + str(case.get("original_language")) + ". " + str(case.get("translation_status")))
    if case["resolution"]:
        st.success("Resolution / latest note: " + case["resolution"])
    if user["role"] != "Complainant":
        with st.expander("Internal review details"):
            st.write("AI/rules suggestion: " + str(case.get("ai_category") or "Not recorded"))
            st.write("Suggested bureau: " + str(case.get("ai_bureau") or "Not recorded"))
            st.write(case.get("ai_explanation") or "")
            if case.get("duplicate_of"):
                st.warning(f"Potentially similar to {case['duplicate_of']} (score {case.get('duplicate_score')}).")
            if case.get("group_id"):
                st.write(f"Related issue group: {case['group_id']}")
            if case.get("confidential_note"):
                st.write("Confidential internal note: " + case["confidential_note"])
    if user["role"] == "Complainant" and case["status"] in ("Resolved", "Closed"):
        st.markdown("#### Resolution feedback")
        current_score = case.get("satisfaction_score")
        score = st.select_slider("How satisfied are you with this resolution?", options=[1,2,3,4,5], value=int(current_score) if current_score else 3, key=f"feedback_score_{tracking}")
        feedback_note = st.text_area("Optional feedback", value=case.get("resolution_feedback") or "", key=f"feedback_note_{tracking}")
        if st.button("Save resolution feedback", key=f"save_feedback_{tracking}"):
            with connect() as con:
                con.execute("UPDATE complaints SET satisfaction_score=?,resolution_feedback=?,updated_at=? WHERE tracking_id=? AND complainant=?",(int(score),feedback_note.strip(),now_text(),tracking,user["username"]))
                con.commit()
            audit_event(user["username"],"Resolution feedback submitted",tracking,f"Satisfaction score {score}/5")
            st.success("Feedback saved."); st.rerun()
    st.markdown("#### Activity timeline")
    for ev in all_activity(tracking):
        st.markdown(f"**{ev['action']}** · {ev['created_at']}  \n{ev['actor']} — {ev['note'] or 'No additional note'}")

LANGUAGE_COPY = {
    "English": {"title":"Complaint title *", "institution":"Institution name *", "state":"State / UT", "category":"Your best-fit category", "priority":"Priority", "email":"Contact email (optional)", "details":"Complaint details *", "confirm":"I confirm this information is accurate to the best of my knowledge.", "submit":"Analyze and submit", "language":"Complaint language"},
    "தமிழ்": {"title":"புகார் தலைப்பு *", "institution":"கல்வி நிறுவனத்தின் பெயர் *", "state":"மாநிலம் / யூனியன் பிரதேசம்", "category":"பொருத்தமான புகார் வகை", "priority":"முன்னுரிமை", "email":"மின்னஞ்சல் (விருப்பத்தேர்வு)", "details":"புகார் விவரங்கள் *", "confirm":"இந்தத் தகவல் எனக்குத் தெரிந்தவரை சரியானது என்பதை உறுதிப்படுத்துகிறேன்.", "submit":"பகுத்து சமர்ப்பிக்கவும்", "language":"புகார் மொழி"},
    "हिन्दी": {"title":"शिकायत का शीर्षक *", "institution":"संस्थान का नाम *", "state":"राज्य / केंद्र शासित प्रदेश", "category":"उपयुक्त शिकायत श्रेणी", "priority":"प्राथमिकता", "email":"संपर्क ईमेल (वैकल्पिक)", "details":"शिकायत का विवरण *", "confirm":"मैं पुष्टि करता/करती हूँ कि यह जानकारी मेरी जानकारी के अनुसार सही है।", "submit":"जाँचें और जमा करें", "language":"शिकायत की भाषा"}
}

def translate_to_english_optional(title, description, language, confidential=False):
    """Optional translation. Never sends confidential complaint content to an external model."""
    if language == "English":
        return title, description, "Not required"
    if confidential:
        return "", "", "Needs translation (confidential: external translation disabled)"
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        return "", "", "Needs translation (no API key; original preserved)"
    try:
        import urllib.request
        prompt = ("Translate the following complaint title and description into clear English. "
                  "Return ONLY JSON with string keys title and description. Do not add facts.\n"
                  f"Source language: {language}\nTitle: {title}\nDescription: {description}")
        body = json.dumps({"model": os.getenv("CLAUDE_MODEL", "claude-sonnet-5-5"), "max_tokens": 700,
                           "messages": [{"role": "user", "content": prompt}]}).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers={
            "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = json.loads(resp.read())["content"][0]["text"]
        data = json.loads(re.search(r"\{.*\}", raw, re.S).group(0))
        et, ed = str(data.get("title", "")).strip(), str(data.get("description", "")).strip()
        if et and ed:
            return et, ed, "Translated to English (LLM; review required)"
    except Exception:
        pass
    return "", "", "Needs translation (translation service unavailable; original preserved)"

def submit_form(user):
    st.subheader("Register a new complaint")
    language = st.selectbox("Complaint language / புகார் மொழி / शिकायत की भाषा", ["English", "தமிழ்", "हिन्दी"], key="complaint_language")
    labels = LANGUAGE_COPY[language]
    with st.form("submit_complaint", clear_on_submit=True):
        left, right = st.columns(2)
        with left:
            title = st.text_input(labels["title"])
            institution = st.text_input(labels["institution"])
            inst_type = st.selectbox("Institution type", ["Engineering College","University","Polytechnic","Management Institute","Arts & Science College","Technical Institute","Other"])
            state = st.text_input(labels["state"])
            category = st.selectbox(labels["category"], CATEGORIES, index=len(CATEGORIES)-1)
        with right:
            priority = st.selectbox(labels["priority"], PRIORITIES, index=1)
            email = st.text_input(labels["email"])
            confidential = st.checkbox("Mark complaint confidential / புகாரை ரகசியமாக வைத்திருக்கவும்")
            st.caption("Confidential cases are restricted to administrators and the assigned officer. External translation is disabled for confidential complaints.")
        description = st.text_area(labels["details"], height=150)
        accurate = st.checkbox(labels["confirm"])
        submit = st.form_submit_button(labels["submit"], type="primary")
    if not submit:
        return
    if not title.strip() or not institution.strip() or not description.strip():
        st.error("Please fill in the title, institution and complaint details.")
        return
    if not accurate:
        st.error("Please confirm the accuracy of the information.")
        return
    english_title, english_description, translation_status = translate_to_english_optional(title.strip(), description.strip(), language, confidential)
    suggestion = classify_rules(title, description, institution)
    dups = duplicate_matches(title, description, institution)
    st.markdown("#### Rules-first triage")
    a,b,c = st.columns(3)
    a.metric("Suggested category", suggestion["category"])
    b.metric("Suggested bureau", suggestion["bureau"])
    c.metric("Indicative confidence", f"{suggestion['confidence']:.0%}")
    st.caption(suggestion["explanation"])
    if language != "English":
        if english_description:
            st.info("English translation is available for officer review. The original-language complaint is preserved.")
            with st.expander("Preview English translation"):
                st.write("**Title:** " + english_title)
                st.write(english_description)
        else:
            st.warning("Original complaint will be saved. English translation status: " + translation_status)
    if dups:
        st.warning("Potentially similar cases found. A human reviewer should check these.")
        st.dataframe(pd.DataFrame(dups).rename(columns={"tracking_id":"Tracking ID","title":"Complaint","institution":"Institution","status":"Status","score":"Similarity"}), hide_index=True, use_container_width=True)
    now = datetime.now()
    tracking = f"AICTE-{now.strftime('%Y%m')}-{int(now.timestamp())%100000:05d}"
    due = (now + timedelta(days=SLA_DAYS[priority])).date().isoformat()
    dup = dups[0] if dups and dups[0]["score"] >= .50 else None
    with connect() as con:
        con.execute("""INSERT INTO complaints
        (tracking_id,title,description,institution,institution_type,state,category,priority,status,bureau,assigned_to,
        complainant,complainant_email,submitted_at,updated_at,due_date,is_confidential,ai_category,ai_bureau,
        ai_explanation,duplicate_of,duplicate_score,original_language,english_translation,translation_status)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (tracking,title.strip(),description.strip(),institution.strip(),inst_type,state.strip(),category,priority,"Submitted",
         ROUTE.get(category,suggestion["bureau"]),None,user["username"],email.strip(),now.isoformat(timespec="minutes"),
         now.isoformat(timespec="minutes"),due,int(confidential),suggestion["category"],suggestion["bureau"],
         suggestion["method"]+": "+suggestion["explanation"],dup["tracking_id"] if dup else None,dup["score"] if dup else None,
         language, ("Title: "+english_title+"\n\n"+english_description) if english_description else None, translation_status))
        con.commit()
    log_activity(tracking,user["username"],"Complaint submitted",f"Due date: {due}. Language: {language}. Translation: {translation_status}. Rules suggested {suggestion['category']} / {suggestion['bureau']}.")
    notify("admin",tracking,"New complaint submitted",f"{tracking}: {title.strip()} is awaiting review.")
    if dup:
        log_activity(tracking,user["username"],"Potential duplicate flagged",f"Similar to {dup['tracking_id']} (score {dup['score']}).")
    st.success(f"Submitted successfully! Your tracking ID is **{tracking}**. Initial due date: {due}.")
    st.info("Keep your tracking ID to check progress.")

def case_update(user, df, admin_mode):
    st.subheader("Assign, update or escalate a complaint")
    if df.empty:
        st.info("No accessible cases.")
        return
    tracking = st.selectbox("Select complaint", df["tracking_id"].tolist(), format_func=lambda x:fmt_case_label(df,x))
    r = df[df["tracking_id"]==tracking].iloc[0]
    if r.get("is_confidential") and user["role"] != "Administrator" and r.get("assigned_to") != user["username"]:
        st.error("Confidential case: access is restricted.")
        return
    # --- AI Case Assistant (wow factor 2) ---
    res_key = f"res_{tracking}"
    if res_key not in st.session_state:
        st.session_state[res_key] = r["resolution"] if isinstance(r["resolution"], str) else ""
    ai_assistant_panel(r, tracking, res_key)
    st.markdown("#### Explainable priority recommendation")
    priority_reasons=[]
    title_desc=(str(r.get("title", ""))+" "+str(r.get("description", ""))).lower()
    if any(term in title_desc for term in ["fire", "collapse", "electric shock", "unsafe building", "harassment", "ragging", "threat"]): priority_reasons.append("Potential immediate safety or student-protection concern appears in the text")
    if is_overdue(r): priority_reasons.append("The case has passed its SLA due date")
    if r.get("duplicate_of"): priority_reasons.append("A potentially related complaint was detected")
    if not priority_reasons: priority_reasons.append("No high-risk keyword or overdue signal detected by the simple rules")
    rec_priority="Critical" if any("safety" in x or "protection" in x for x in priority_reasons) and is_overdue(r) else ("High" if any("safety" in x or "protection" in x for x in priority_reasons) else ("High" if is_overdue(r) else r["priority"]))
    st.write("**Suggested priority:**", rec_priority, "· **Current priority:**", r["priority"])
    for reason in priority_reasons: st.caption("• "+reason)
    st.caption("Recommendation only. An authorized officer must decide the final priority.")
    with st.form("update_case"):
        c1,c2 = st.columns(2)
        with c1:
            status = st.selectbox("Status",STATUSES,index=STATUSES.index(r["status"]) if r["status"] in STATUSES else 0)
            priority = st.selectbox("Priority",PRIORITIES,index=PRIORITIES.index(r["priority"]) if r["priority"] in PRIORITIES else 1)
            due = st.date_input("SLA due date", value=date.fromisoformat(str(r["due_date"])[:10]) if r["due_date"] else date.today()+timedelta(days=7))
            group_id = st.text_input("Related issue group ID", value=r.get("group_id") or "", help="Use the same group ID for complaints about the same recurring issue.")
        with c2:
            bureau = st.selectbox("Responsible bureau",BUREAUS,index=BUREAUS.index(r["bureau"]) if r["bureau"] in BUREAUS else len(BUREAUS)-1,disabled=not admin_mode)
            assigned = st.text_input("Assigned officer username",value=r["assigned_to"] or "",disabled=not admin_mode)
            resolution = st.text_area("Resolution / update",key=res_key,height=90)
            confidential_note = st.text_area("Confidential internal note",value=r.get("confidential_note") or "",height=70) if admin_mode else ""
        note = st.text_area("Activity note")
        save = st.form_submit_button("Save case update",type="primary")
    if save:
        old_status = r["status"]
        new_bureau = bureau if admin_mode else r["bureau"]
        new_assigned = assigned.strip() or None if admin_mode else r["assigned_to"]
        with connect() as con:
            con.execute("""UPDATE complaints SET status=?,priority=?,due_date=?,bureau=?,assigned_to=?,resolution=?,
            group_id=?,confidential_note=?,updated_at=? WHERE tracking_id=?""",
            (status,priority,due.isoformat(),new_bureau,new_assigned,resolution.strip() or None,
             group_id.strip() or None,confidential_note.strip() or None,now_text(),tracking))
            con.commit()
        log_activity(tracking,user["username"],f"Case updated: {status}",note.strip() or resolution.strip())
        if status != old_status:
            notify(r["complainant"],tracking,"Complaint status updated",f"{tracking} status changed to {status}.")
        if admin_mode and (new_bureau != r["bureau"] or new_assigned != r["assigned_to"]):
            notify(new_assigned,tracking,"Complaint assigned to you",f"{tracking} has been assigned to your account.")
            log_activity(tracking,user["username"],"Assignment changed",f"Bureau: {new_bureau}; officer: {new_assigned or 'unassigned'}.")
        st.success("Case updated.")
        st.rerun()

def coordination_panel(user, df, admin_mode):
    st.subheader("Multi-bureau coordination")
    st.caption("Request input from another bureau without losing the lead bureau's ownership of the case.")
    if df.empty:
        st.info("No cases available.")
        return
    tracking = st.selectbox("Complaint for coordination",df["tracking_id"].tolist(),format_func=lambda x:fmt_case_label(df,x),key="coord_tracking")
    r = df[df["tracking_id"]==tracking].iloc[0]
    with st.form("bureau_request"):
        target = st.selectbox("Request support from", [b for b in BUREAUS if b != r["bureau"]])
        note = st.text_area("Action requested *",placeholder="Explain the information or action needed.")
        create = st.form_submit_button("Send bureau request",type="primary")
    if create:
        if not note.strip():
            st.error("Please describe the requested action.")
        else:
            with connect() as con:
                con.execute("""INSERT INTO bureau_requests(tracking_id,requesting_bureau,target_bureau,requested_by,
                request_note,status,created_at,updated_at) VALUES(?,?,?,?,?,'Pending',?,?)""",
                (tracking,r["bureau"] or "Other / Needs Review",target,user["username"],note.strip(),now_text(),now_text()))
                con.commit()
            log_activity(tracking,user["username"],"Cross-bureau request created",f"To {target}: {note.strip()}")
            notify("admin",tracking,"Cross-bureau action requested",f"{tracking}: action requested from {target}.")
            st.success("Support request created.")
            st.rerun()
    with connect() as con:
        requests = con.execute("SELECT * FROM bureau_requests ORDER BY created_at DESC").fetchall()
    if not requests:
        st.info("No cross-bureau requests yet.")
        return
    st.markdown("#### Existing requests")
    for req in requests:
        if user["role"] == "Bureau Officer" and req["target_bureau"] != user.get("bureau") and req["requesting_bureau"] != user.get("bureau"):
            continue
        with st.container(border=True):
            st.markdown(f"**{req['tracking_id']}** · {req['requesting_bureau']} → {req['target_bureau']} · **{req['status']}**")
            st.write(req["request_note"])
            if req["response_note"]:
                st.caption("Response: "+req["response_note"])
            if user["role"] == "Administrator" or user.get("bureau") == req["target_bureau"]:
                with st.form(f"respond_{req['id']}"):
                    state = st.selectbox("Request status",["Pending","In Progress","Completed","Declined","Responded"],index=["Pending","In Progress","Completed","Declined","Responded"].index(req["status"]))
                    response = st.text_input("Response note",value=req["response_note"] or "")
                    save = st.form_submit_button("Update request")
                if save:
                    with connect() as con:
                        con.execute("UPDATE bureau_requests SET status=?,response_note=?,updated_at=? WHERE id=?",
                                    (state,response.strip(),now_text(),req["id"]))
                        con.commit()
                    log_activity(req["tracking_id"],user["username"],"Bureau request updated",f"{req['target_bureau']}: {state}. {response}")
                    st.rerun()

def analytics_panel(df):
    st.subheader("Advanced monitoring analytics")
    if df.empty:
        st.info("No complaints available.")
        return
    open_df = df[~df["status"].isin(TERMINAL)]
    resolved = df[df["status"].isin(["Resolved","Closed"])]
    submitted = pd.to_datetime(df["submitted_at"],errors="coerce")
    updated = pd.to_datetime(df["updated_at"],errors="coerce")
    durations = (updated - submitted).dt.total_seconds()/86400
    resolved_durations = durations[df["status"].isin(["Resolved","Closed"])].dropna()
    k1,k2,k3,k4 = st.columns(4)
    k1.metric("Resolution / closure rate",f"{len(resolved)/len(df):.1%}")
    k2.metric("Open backlog",len(open_df))
    k3.metric("Overdue open cases",sum(is_overdue(r) for _,r in open_df.iterrows()))
    k4.metric("Avg. resolution proxy",f"{resolved_durations.mean():.1f} days" if len(resolved_durations) else "N/A")
    l,r = st.columns(2)
    with l:
        st.markdown("#### Cases by bureau")
        st.bar_chart(df["bureau"].fillna("Unassigned").value_counts())
        st.markdown("#### Cases by priority")
        st.bar_chart(df["priority"].value_counts())
    with r:
        st.markdown("#### Status distribution")
        st.bar_chart(df["status"].value_counts())
        st.markdown("#### Category trends")
        st.bar_chart(df["category"].value_counts())
    bureau_stats = df.assign(overdue=df.apply(is_overdue,axis=1)).groupby("bureau",dropna=False).agg(
        Total=("tracking_id","count"), Overdue=("overdue","sum"),
        Resolved=("status",lambda s:int(s.isin(["Resolved","Closed"]).sum()))
    ).reset_index()
    bureau_stats["Resolution rate"] = (bureau_stats["Resolved"]/bureau_stats["Total"]).fillna(0).map(lambda x:f"{x:.1%}")
    st.markdown("#### Bureau performance")
    st.dataframe(bureau_stats.rename(columns={"bureau":"Bureau"}),use_container_width=True,hide_index=True)
    st.caption("Average resolution proxy uses updated_at minus submitted_at for resolved/closed cases; it is an approximation, not a dedicated resolution timestamp.")

def make_pdf(df, title="AICTE Complaint Desk Report"):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        import io
        buf=io.BytesIO()
        doc=SimpleDocTemplate(buf,pagesize=landscape(A4),rightMargin=12*mm,leftMargin=12*mm,topMargin=12*mm,bottomMargin=12*mm)
        styles=getSampleStyleSheet()
        story=[Paragraph(title,styles["Title"]),Paragraph(f"Generated: {now_text()} · Records: {len(df)}",styles["Normal"]),Spacer(1,8)]
        cols=["tracking_id","title","institution","category","priority","status","bureau","due_date"]
        data=[["Tracking ID","Complaint","Institution","Category","Priority","Status","Bureau","Due date"]]
        for _,row in df[cols].fillna("").iterrows():
            data.append([str(row[c])[:100] for c in cols])
        table=Table(data,repeatRows=1,colWidths=[25*mm,48*mm,38*mm,32*mm,18*mm,25*mm,35*mm,22*mm])
        table.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1d4ed8")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),7),
            ("GRID",(0,0),(-1,-1),.3,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP"),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#eff6ff")])
        ]))
        story.append(table)
        doc.build(story)
        return buf.getvalue()
    except ImportError:
        return None

# ======================= WOW FACTOR 1: HOTSPOTS + EARLY WARNING =======================
STATE_COORDS = {
    "andhra pradesh": (15.9129, 79.7400), "arunachal pradesh": (28.2180, 94.7278),
    "assam": (26.2006, 92.9376), "bihar": (25.0961, 85.3131), "chhattisgarh": (21.2787, 81.8661),
    "delhi": (28.6139, 77.2090), "goa": (15.2993, 74.1240), "gujarat": (22.2587, 71.1924),
    "haryana": (29.0588, 76.0856), "himachal pradesh": (31.1048, 77.1734),
    "jharkhand": (23.6102, 85.2799), "karnataka": (15.3173, 75.7139), "kerala": (10.8505, 76.2711),
    "madhya pradesh": (22.9734, 78.6569), "maharashtra": (19.7515, 75.7139),
    "manipur": (24.6637, 93.9063), "meghalaya": (25.4670, 91.3662), "mizoram": (23.1645, 92.9376),
    "nagaland": (26.1584, 94.5624), "odisha": (20.9517, 85.0985), "punjab": (31.1471, 75.3412),
    "rajasthan": (27.0238, 74.2179), "sikkim": (27.5330, 88.5122), "tamil nadu": (11.1271, 78.6569),
    "telangana": (18.1124, 79.0193), "tripura": (23.9408, 91.9882),
    "uttar pradesh": (26.8467, 80.9462), "uttarakhand": (30.0668, 79.0193),
    "west bengal": (22.9868, 87.8550), "jammu and kashmir": (33.7782, 76.5762),
    "jammu kashmir": (33.7782, 76.5762), "ladakh": (34.1526, 77.5770),
    "puducherry": (11.9416, 79.8083), "chandigarh": (30.7333, 76.7794),
}
PRIORITY_WEIGHT = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

def case_risk(row):
    if row["status"] in TERMINAL:
        return 0
    return PRIORITY_WEIGHT.get(row["priority"], 1) + (2 if is_overdue(row) else 0)

def hotspot_frame(df):
    cols = ["State", "lat", "lon", "Open cases", "Critical", "Overdue", "Risk score", "Top category", "size", "color"]
    if df.empty:
        return pd.DataFrame(columns=cols)
    open_df = df[~df["status"].isin(TERMINAL)].copy()
    open_df["_st"] = open_df["state"].fillna("").map(normalize)
    rows = []
    for st_key, g in open_df.groupby("_st"):
        if st_key not in STATE_COORDS:
            continue
        lat, lon = STATE_COORDS[st_key]
        critical = int((g["priority"] == "Critical").sum())
        overdue = int(sum(is_overdue(r) for _, r in g.iterrows()))
        risk = int(sum(case_risk(r) for _, r in g.iterrows()))
        rows.append({
            "State": str(g["state"].iloc[0]).strip().title(), "lat": lat, "lon": lon,
            "Open cases": len(g), "Critical": critical, "Overdue": overdue, "Risk score": risk,
            "Top category": g["category"].value_counts().index[0],
            "size": 30000 + risk * 20000,
            "color": "#dc2626" if (critical or overdue) else ("#f59e0b" if risk >= 3 else "#2563eb"),
        })
    return pd.DataFrame(rows, columns=cols)

def early_warnings(df, window_days=30):
    """Detect clusters of similar open complaints that may signal a systemic issue."""
    if df.empty:
        return []
    d = df[~df["status"].isin(TERMINAL)].copy()
    d["_ts"] = pd.to_datetime(d["submitted_at"], errors="coerce")
    d = d[d["_ts"] >= datetime.now() - timedelta(days=window_days)]
    if d.empty:
        return []
    d["_inst"] = d["institution"].map(normalize)
    out = []

    def pack(g, level, headline, detail, category):
        gids = set(g["group_id"].fillna("").astype(str))
        out.append({
            "level": level, "headline": headline, "detail": detail,
            "trackings": g["tracking_id"].tolist(),
            "label": re.sub(r"[^A-Z]", "", category.upper())[:12] or "CASE",
            "grouped": len(gids) == 1 and "" not in gids,
        })

    for (_, cat), g in d.groupby(["_inst", "category"]):
        if len(g) >= 2:
            crit = bool((g["priority"] == "Critical").any())
            level = "Alert" if (len(g) >= 3 or crit) else "Watch"
            name = g["institution"].iloc[0]
            pack(g, level, f"{len(g)} '{cat}' complaints at {name}",
                 f"Raised within the last {window_days} days. Possible institution-level problem.", cat)
    for cat, g in d.groupby("category"):
        n_inst = g["_inst"].nunique()
        if len(g) >= 3 and n_inst >= 2:
            pack(g, "Alert", f"{len(g)} '{cat}' complaints across {n_inst} institutions",
                 f"Pattern across institutions in the last {window_days} days. Possible policy or systemic issue.", cat)
    out.sort(key=lambda w: (w["level"] != "Alert", -len(w["trackings"])))
    return out

def create_group(trackings, actor, label):
    marks = ",".join("?" * len(trackings))
    with connect() as con:
        existing = con.execute(
            f"SELECT group_id FROM complaints WHERE tracking_id IN ({marks}) AND group_id IS NOT NULL AND group_id<>'' LIMIT 1",
            trackings).fetchone()
        gid = existing["group_id"] if existing else f"GRP-{label}-{date.today():%y%m%d}"
        con.execute(f"UPDATE complaints SET group_id=?, updated_at=? WHERE tracking_id IN ({marks})",
                    [gid, now_text(), *trackings])
        con.commit()
    for t in trackings:
        log_activity(t, actor, "Grouped by early-warning radar", f"Related issue group: {gid}")
    return gid

def hotspot_panel(df, user):
    st.subheader("Hotspot map & early-warning radar")
    st.caption("Open cases only. Bubble size = risk (priority + overdue weight). Red = has critical or overdue cases.")
    if df.empty:
        st.info("No complaints available.")
        return
    hs = hotspot_frame(df)
    warnings = early_warnings(df)
    c1, c2, c3 = st.columns(3)
    c1.metric("States with open cases", len(hs))
    c2.metric("Red-zone states", int((hs["color"] == "#dc2626").sum()))
    c3.metric("Early-warning signals", len(warnings))
    if hs.empty:
        st.info("No open cases with a recognised state.")
    else:
        st.map(hs, latitude="lat", longitude="lon", size="size", color="color")
        st.dataframe(hs[["State", "Open cases", "Critical", "Overdue", "Risk score", "Top category"]]
                     .sort_values("Risk score", ascending=False),
                     use_container_width=True, hide_index=True)
    st.markdown("#### 🚨 Early-warning radar")
    if not warnings:
        st.success("No clusters detected. Nothing unusual in the last 30 days.")
    for i, w in enumerate(warnings):
        with st.container(border=True):
            st.markdown(f"{'🔴' if w['level'] == 'Alert' else '🟠'} **{w['level']} · {w['headline']}**")
            st.caption(w["detail"])
            st.write("Cases: " + ", ".join(w["trackings"]))
            if w["grouped"]:
                st.caption("✅ Already grouped as one related issue.")
            elif user["role"] == "Administrator":
                if st.button("Group these cases as one issue", key=f"grp_{i}"):
                    gid = create_group(w["trackings"], user["username"], w["label"])
                    st.toast(f"Grouped under {gid}")
                    st.rerun()

# ======================= WOW FACTOR 2: AI CASE ASSISTANT =======================
URGENCY_TERMS = ["urgent", "immediately", "safety", "electrical", "fire", "injury", "unsafe", "threat",
                 "harass", "ragging", "deadline", "exam"]
DISTRESS_TERMS = ["afraid", "scared", "unsafe", "threat", "fear", "retaliation", "danger", "injury", "harass"]
FRUSTRATION_TERMS = ["no response", "ignored", "not received", "not credited", "repeatedly", "still",
                     "months", "unacceptable", "pending", "delay"]
NEXT_STEPS = {
    "Approval / Affiliation": ["Check the institution's application status in the approval records",
                               "Confirm the cycle and documents submitted", "Share a clear status note with the complainant"],
    "Institution Infrastructure": ["Request an inspection or compliance report from the institution",
                                   "Ask for photos or documents showing the current condition", "Set a follow-up date for corrective action"],
    "Faculty / Staff": ["Compare the faculty details with the institution's latest submission",
                        "Request the staff list from the institution", "Flag mismatches to the Administration Bureau"],
    "Student Welfare": ["Acknowledge the concern and assign a named officer",
                        "Contact the institution's grievance committee", "Check in with the complainant on progress"],
    "Examination / Academic": ["Ask for the mark sheet and the relevant notification",
                               "Contact the university or exam cell for verification", "Record the correction request and timeline"],
    "Fee / Finance": ["Request the payment reference and receipt", "Ask the institution for its refund policy and status",
                      "Check for similar fee complaints at the same institution"],
    "Scholarship": ["Verify the release timeline with the Finance Bureau", "Check for other complaints from the same institution",
                    "Inform the complainant of the expected date"],
    "Discrimination / Harassment": ["Handle confidentially and limit case access", "Contact the complainant through a safe channel",
                                    "Escalate to the Student Grievance Cell lead"],
    "Other": ["Review manually and confirm the correct bureau", "Ask the complainant for missing details"],
}

def analyze_case_offline(case):
    text = normalize(f"{case.get('title')} {case.get('description')}")
    hits = lambda terms: [t for t in terms if t in text]
    urg, dis, fru = hits(URGENCY_TERMS), hits(DISTRESS_TERMS), hits(FRUSTRATION_TERMS)
    score = {"Low": 10, "Medium": 25, "High": 45, "Critical": 65}.get(case.get("priority"), 25)
    score += min(24, 8 * len(urg)) + min(8, 4 * len(dis)) + (15 if is_overdue(case) else 0)
    score = min(100, score)
    label = "Immediate" if score >= 80 else "High" if score >= 55 else "Moderate" if score >= 30 else "Routine"
    tone = "Distressed" if dis else ("Frustrated" if len(fru) >= 2 else "Neutral")
    sentences = re.split(r"(?<=[.!?])\s+", str(case.get("description") or "").strip())
    summary = " ".join(sentences[:2])[:300]
    steps = NEXT_STEPS.get(case.get("category"), NEXT_STEPS["Other"])
    empathy = {"Distressed": "We understand this is a worrying situation and we are treating it with care.",
               "Frustrated": "We are sorry for the delay and inconvenience you have experienced.",
               "Neutral": "We appreciate you taking the time to report this."}[tone]
    draft = (
        f"Dear Complainant,\n\n"
        f"Thank you for bringing this matter to our attention. Your complaint {case.get('tracking_id')} "
        f"regarding \"{case.get('title')}\" has been registered and routed to the {case.get('bureau') or 'concerned bureau'}.\n\n"
        f"{empathy} The case is marked {case.get('priority')} priority and we aim to share an update by "
        f"{case.get('due_date') or 'the earliest possible date'}.\n\n"
        f"To help us proceed, please share any supporting details (reference numbers, dates, screenshots or letters).\n\n"
        f"Regards,\n{case.get('bureau') or 'Complaint Desk'}\nAICTE Complaint Desk (prototype)"
    )
    return {"score": score, "label": label, "tone": tone, "summary": summary,
            "next_steps": steps, "reply_draft": draft, "source": "Rules engine (offline)"}

def analyze_case_llm(case):
    """Optional upgrade: runs only if ANTHROPIC_API_KEY is set. Never used for confidential cases."""
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key or case.get("is_confidential"):
        return None
    try:
        import urllib.request
        prompt = (
            "You assist an Indian education regulator's complaint desk (fictional prototype). "
            "Return ONLY JSON with keys: summary (max 2 sentences), tone (Neutral|Frustrated|Distressed), "
            "next_steps (list of 3 short strings), reply_draft (polite, no promises of outcome, under 120 words).\n\n"
            f"Title: {case.get('title')}\nCategory: {case.get('category')}\nPriority: {case.get('priority')}\n"
            f"Bureau: {case.get('bureau')}\nDescription: {case.get('description')}"
        )
        body = json.dumps({"model": os.getenv("CLAUDE_MODEL", "claude-sonnet-5-5"), "max_tokens": 700,
                           "messages": [{"role": "user", "content": prompt}]}).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers={
            "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            text = json.loads(resp.read())["content"][0]["text"]
        data = json.loads(re.search(r"\{.*\}", text, re.S).group(0))
        out = {}
        if isinstance(data.get("summary"), str): out["summary"] = data["summary"]
        if data.get("tone") in ("Neutral", "Frustrated", "Distressed"): out["tone"] = data["tone"]
        if isinstance(data.get("next_steps"), list): out["next_steps"] = [str(s) for s in data["next_steps"][:4]]
        if isinstance(data.get("reply_draft"), str): out["reply_draft"] = data["reply_draft"]
        return out or None
    except Exception:
        return None

def analyze_case(case):
    result = analyze_case_offline(case)
    llm = analyze_case_llm(case)
    if llm:
        result.update(llm)
        result["source"] = "LLM + rules guardrails (score from rules)"
    return result

def _use_draft(res_key, draft):
    st.session_state[res_key] = draft

def ai_assistant_panel(r, tracking, res_key):
    key = f"ai_{tracking}"
    with st.expander("🤖 AI Case Assistant: summary, urgency and draft reply"):
        if st.button("Analyze this case", key=f"ai_btn_{tracking}"):
            with st.spinner("Analyzing case..."):
                st.session_state[key] = analyze_case(r.to_dict())
        a = st.session_state.get(key)
        if not a:
            st.caption("Click Analyze to get an urgency score, tone, summary, next steps and a draft reply.")
            return
        m1, m2, m3 = st.columns(3)
        m1.metric("Urgency score", f"{a['score']}/100")
        m2.metric("Attention level", a["label"])
        m3.metric("Complainant tone", a["tone"])
        st.progress(a["score"] / 100)
        st.markdown("**Summary**")
        st.write(a["summary"])
        st.markdown("**Suggested next steps**")
        for s in a["next_steps"]:
            st.write("- " + s)
        st.markdown("**Suggested reply draft**")
        st.code(a["reply_draft"], language=None)
        st.button("Use this draft as the resolution / update", key=f"use_draft_{tracking}",
                  on_click=_use_draft, args=(res_key, a["reply_draft"]))
        st.caption(f"Source: {a['source']}. This is a suggestion; an officer must review before it is sent.")


def institution_scorecard(df):
    st.subheader("Institution Risk Scorecard")
    st.caption("Heuristic oversight indicator, not an official accreditation or compliance decision. Higher score = greater attention needed.")
    if df.empty:
        st.info("No complaint data available yet."); return
    rows=[]
    for institution, g in df.groupby(df["institution"].fillna("Unknown institution")):
        open_cases=g[~g["status"].isin(TERMINAL)]
        overdue=sum(is_overdue(r) for _,r in open_cases.iterrows())
        critical=int((open_cases["priority"]=="Critical").sum())
        high=int((open_cases["priority"]=="High").sum())
        resolved=int(g["status"].isin(["Resolved","Closed"]).sum())
        total=len(g)
        # Transparent heuristic: open volume + urgency + overdue + repeated category + weak resolution rate.
        repeat_categories=int(g["category"].value_counts().gt(1).sum())
        resolution_rate=resolved/total if total else 0
        raw=min(100, len(open_cases)*5 + high*8 + critical*15 + overdue*12 + repeat_categories*5 + (1-resolution_rate)*20)
        rows.append({"Institution":institution,"Risk score (0-100)":int(round(raw)),"Level":"High attention" if raw>=60 else ("Moderate attention" if raw>=30 else "Routine monitoring"),"Total complaints":total,"Open":len(open_cases),"Overdue":overdue,"Critical open":critical,"Resolution rate":round(resolution_rate*100,1)})
    score=pd.DataFrame(rows).sort_values(["Risk score (0-100)","Overdue","Open"],ascending=False)
    st.dataframe(score,hide_index=True,use_container_width=True)
    st.download_button("Download institution scorecard CSV",score.to_csv(index=False).encode("utf-8"),"institution_risk_scorecard.csv","text/csv")
    st.caption("Score formula uses open cases, high/critical cases, overdue cases, repeated categories and resolution rate. Review the underlying cases before taking action.")

def public_transparency_page():
    """Public aggregate-only dashboard; excludes institution names, tracking IDs and personal data."""
    st.markdown("## 🌐 Public Complaint Transparency")
    st.caption("Public, aggregate-only view. No complainant names, contact details, tracking IDs, complaint text, or institution names are displayed. Prototype statistics use the current local demo database.")
    all_df=all_complaints()
    if all_df.empty:
        st.info("No aggregate statistics are available yet."); return
    total=len(all_df); closed=int(all_df["status"].isin(["Resolved","Closed"]).sum())
    avg_days=None
    resolved=all_df[all_df["status"].isin(["Resolved","Closed"])].copy()
    if not resolved.empty:
        try:
            avg_days=(pd.to_datetime(resolved["updated_at"])-pd.to_datetime(resolved["submitted_at"])).dt.total_seconds().div(86400).clip(lower=0).mean()
        except Exception: avg_days=None
    a,b,c=st.columns(3);a.metric("Total complaints",total);b.metric("Resolution rate",f"{closed/total:.1%}" if total else "0%")
    c.metric("Average time to resolution",f"{avg_days:.1f} days" if pd.notna(avg_days) else "Not available")
    st.markdown("#### Complaint counts by state")
    state_counts=all_df[all_df["state"].fillna("").ne("")].groupby("state").size().sort_values(ascending=False)
    if not state_counts.empty: st.bar_chart(state_counts)
    st.markdown("#### Complaint counts by category")
    category_counts=all_df.groupby("category").size().sort_values(ascending=False)
    if not category_counts.empty: st.bar_chart(category_counts)
    st.markdown("#### Status summary")
    st.bar_chart(all_df["status"].value_counts())
    st.caption("Transparency page is a hackathon prototype. Counts may include fictional demo records and should not be interpreted as official AICTE statistics.")

# ------------------------------- Main app ----------------------------------
init_db()
run_sla_sweep()
if "user" not in st.session_state:
    st.session_state.user = None

st.markdown("""<style>
.block-container{padding-top:1.25rem;max-width:1500px;padding-bottom:3rem}
.hero{padding:1.55rem 1.7rem;border-radius:18px;background:linear-gradient(115deg,#0b1224 0%,#153e75 58%,#2563eb 100%);color:white;margin:0 0 1.25rem;box-shadow:0 10px 30px rgba(15,23,42,.12)}
.hero h1{margin:0;font-size:2.05rem;letter-spacing:-.03em;font-weight:750}.hero p{margin:.45rem 0 0;opacity:.88;font-size:1rem}
section[data-testid="stSidebar"]{border-right:1px solid rgba(148,163,184,.25)}
.stTabs [data-baseweb="tab-list"]{gap:7px;border-bottom:1px solid rgba(148,163,184,.3)}
.stTabs [data-baseweb="tab"]{height:45px;padding:0 15px;border-radius:10px 10px 0 0;font-weight:600}
.stButton>button,.stDownloadButton>button{border-radius:10px;font-weight:600;min-height:2.55rem}
.stTextInput input,.stTextArea textarea,.stSelectbox [data-baseweb="select"]{border-radius:10px}
div[data-testid="stMetric"]{border:1px solid rgba(100,116,139,.28);padding:14px 16px;border-radius:14px;background:rgba(148,163,184,.055);box-shadow:0 2px 8px rgba(15,23,42,.025)}
div[data-testid="stMetricLabel"]{font-weight:600}
div[data-testid="stDataFrame"]{border:1px solid rgba(100,116,139,.2);border-radius:12px;overflow:hidden}
hr{margin:1.5rem 0;border-color:rgba(148,163,184,.25)}
</style>""",unsafe_allow_html=True)

if not st.session_state.user:
    st.markdown('<div class="hero"><h1>🏛️ AICTE Complaint Desk</h1><p>Cross-bureau complaint monitoring, SLA accountability and case coordination.</p></div>',unsafe_allow_html=True)
    a,b=st.columns([1.2,1])
    with a:
        st.subheader("A single case register across bureaus")
        st.markdown("- SLA deadline tracking and overdue escalation\n- Rules-first complaint triage\n- Cross-bureau action requests\n- Related complaint grouping\n- Hotspot map and early-warning radar\n- AI case assistant with draft replies\n- Performance analytics and PDF reports\n- Role-based case access and notification center")
        st.info("Hackathon prototype only; not an official AICTE service.")
    with b:
        with st.form("login"):
            username=st.text_input("Username")
            password=st.text_input("Password",type="password")
            go=st.form_submit_button("Sign in",type="primary",use_container_width=True)
        if go:
            u=get_user(username.strip())
            if u and verify_password(u["password"], password):
                if not u["password"].startswith("pbkdf2_sha256$"):
                    with connect() as con:
                        con.execute("UPDATE users SET password=? WHERE username=?", (password_hash(password), username.strip()))
                        con.commit()
                    u=get_user(username.strip())
                audit_event(username.strip(), "Successful login", None, "Role: "+u["role"])
                st.session_state.user=dict(u);st.rerun()
            else:
                audit_event(username.strip() or "unknown", "Failed login", None, "Invalid credentials")
                st.error("Incorrect username or password.")
        with st.expander("Demo accounts"):
            st.code("Administrator: admin / admin123\nBureau Officer: officer / officer123\nComplainant: student / student123")
    st.divider()
    public_transparency_page()
    st.stop()

user=st.session_state.user
role=user["role"]
df_all=all_complaints()
df=visible_cases(df_all,user)
with st.sidebar:
    st.markdown("## 🏛️ AICTE Desk")
    st.write(f"**{user['full_name']}**")
    st.caption(role + (f" · {user.get('bureau')}" if role=="Bureau Officer" else ""))
    st.caption("AI mode: rules-first + optional LLM")
    if role == "Administrator":
        st.divider()
        st.caption("Presentation tools")
        if st.button("➕ Load fictional demo data", use_container_width=True,
                      help="Adds 12 fictional complaints once; existing records are not changed."):
            added, count = seed_demo_data()
            if added:
                st.success(f"Added {count} fictional demo complaints.")
            else:
                st.info(f"Demo data is already present ({count} demo complaints found). No records were changed.")
            st.rerun()
        st.caption("DEMO-2026 IDs identify fictional sample records.")
    if st.button("Sign out",use_container_width=True):
        st.session_state.user=None;st.rerun()
st.markdown('<div class="hero"><h1>Complaint Monitoring Dashboard</h1><p>Every case has an owner, a deadline and a traceable history.</p></div>',unsafe_allow_html=True)
open_df=df[~df["status"].isin(TERMINAL)] if not df.empty else df
overdue_n=sum(is_overdue(r) for _,r in df.iterrows()) if not df.empty else 0
k1,k2,k3,k4,k5=st.columns(5)
k1.metric("Total cases",len(df));k2.metric("Open cases",len(open_df))
k3.metric("Resolved / closed",int(df["status"].isin(["Resolved","Closed"]).sum()) if not df.empty else 0)
k4.metric("Overdue",overdue_n);k5.metric("High / critical",int((df["priority"].isin(["High","Critical"]) & ~df["status"].isin(TERMINAL)).sum()) if not df.empty else 0)

if role=="Complainant":
    tabs=st.tabs(["My Complaints","Submit Complaint","Filing Assistant","Track by ID","Notifications","Evidence & OCR"])
elif role=="Bureau Officer":
    tabs=st.tabs(["My Bureau","Update Case","Track by ID","Coordination","Notifications","Evidence & OCR"])
else:
    tabs=st.tabs(["Overview","All Complaints","Assign & Update","Track by ID","Coordination","Analytics","Notifications","Reports","Related Groups","Hotspots & Early Warning","Institution Risk Scorecard","Evidence & OCR","Workload","Root Cause","Audit Log","Deadline Reminders","Resolution Quality","Relationship Explorer","What-if Simulator"])

if role=="Complainant":
    with tabs[0]:
        st.subheader("My complaints");render_table(df)
    with tabs[1]: submit_form(user)
    with tabs[2]: filing_assistant_panel()
    with tabs[3]: track_case(user,df)
    with tabs[4]: notification_panel(user)
    with tabs[5]: evidence_panel(user,df)
elif role=="Bureau Officer":
    with tabs[0]:
        st.subheader("Bureau queue")
        filters=st.multiselect("Filter by status",STATUSES)
        render_table(df[df["status"].isin(filters)] if filters else df)
        st.markdown("#### Cases requiring attention")
        render_table(df[df.apply(is_overdue,axis=1)] if not df.empty else df)
    with tabs[1]: case_update(user,df,False)
    with tabs[2]: track_case(user,df)
    with tabs[3]: coordination_panel(user,df,False)
    with tabs[4]: notification_panel(user)
    with tabs[5]: evidence_panel(user,df)
else:
    with tabs[0]:
        _w = early_warnings(df)
        if _w:
            st.warning(f"⚠️ {len(_w)} early-warning signal(s) detected. Open the 'Hotspots & Early Warning' tab.")
        l,r=st.columns(2)
        with l:
            st.markdown("#### Status distribution")
            if not df.empty: st.bar_chart(df["status"].value_counts())
        with r:
            st.markdown("#### Bureau workload")
            if not df.empty: st.bar_chart(df["bureau"].fillna("Unassigned").value_counts())
        st.markdown("#### Recent cases");render_table(df.head(8))
        st.markdown("#### Overdue / high priority cases")
        render_table(df[(df.apply(is_overdue,axis=1)) | (df["priority"].isin(["High","Critical"]) & ~df["status"].isin(TERMINAL))] if not df.empty else df)
    with tabs[1]:
        q=st.text_input("Search tracking ID, title or institution")
        s=st.multiselect("Status filter",STATUSES)
        p=st.multiselect("Priority filter",PRIORITIES)
        view=df.copy()
        if q:
            mask=view[["tracking_id","title","institution"]].fillna("").astype(str).apply(lambda c:c.str.contains(q,case=False,regex=False)).any(axis=1)
            view=view[mask]
        if s:view=view[view["status"].isin(s)]
        if p:view=view[view["priority"].isin(p)]
        render_table(view)
        st.download_button("Export filtered CSV",view.to_csv(index=False).encode("utf-8"),"aicte_complaints.csv","text/csv")
    with tabs[2]: case_update(user,df,True)
    with tabs[3]: track_case(user,df)
    with tabs[4]: coordination_panel(user,df,True)
    with tabs[5]: analytics_panel(df)
    with tabs[6]: notification_panel(user)
    with tabs[7]:
        st.subheader("Reports")
        st.write("Download a CSV or a PDF snapshot of the cases visible to your role.")
        st.download_button("Download all visible cases (CSV)",df.to_csv(index=False).encode("utf-8"),"aicte_report.csv","text/csv")
        pdf=make_pdf(df)
        if pdf:
            st.download_button("Download PDF report",pdf,"aicte_complaint_report.pdf","application/pdf")
        else:
            st.warning("PDF library is not installed. Run: pip install reportlab")
        if not df.empty:
            st.markdown("#### Report summary")
            st.write(f"Records: {len(df)} · Open: {len(open_df)} · Overdue: {overdue_n}")
    with tabs[8]:
        st.subheader("Related complaint groups")
        st.caption("Set the same group ID on cases that appear to concern the same recurring issue. Cases remain individually traceable.")
        groups=df[df["group_id"].fillna("").ne("")] if not df.empty else df
        if groups.empty: st.info("No issue groups yet. Use Assign & Update to set a group ID.")
        else:
            for gid, group in groups.groupby("group_id"):
                with st.expander(f"{gid} · {len(group)} related complaint(s)"):
                    render_table(group)
                    st.write("Institutions: "+", ".join(sorted(group["institution"].dropna().unique().tolist())))
    with tabs[9]: hotspot_panel(df, user)
    with tabs[10]: institution_scorecard(df)
    with tabs[11]: evidence_panel(user,df)
    with tabs[12]: workload_panel(df)
    with tabs[13]: root_cause_panel(df)
    with tabs[14]: audit_panel()
    with tabs[15]: notifications_reminder_panel(df)
    with tabs[16]: resolution_quality_panel(df)
    with tabs[17]: relationship_graph_panel(df)
    with tabs[18]: policy_simulator_panel(df)

st.divider()
st.caption("AICTE Complaint Desk prototype · Demo data should be fictional. Do not enter real sensitive information.")