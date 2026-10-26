\# Ethical Use Statement — CyberRecon



\## Purpose



CyberRecon is an \*\*academic security research artifact\*\* developed at

Amrita School of Computing, Chennai Campus, as part of a Cyber Security

capstone project.



It reproduces the QR-Code-based Command \& Control (C2) technique

\*\*published by Mandiant in 2024\*\* ("(QR) Coding My Way Out of Here: C2 in

Browser Isolation Environments") for the purpose of:



1\. Understanding how browser isolation can be bypassed.

2\. Building \*\*defensive detections\*\* for this class of attack.

3\. Teaching secure-software-supply-chain practices.



\## Authorized Use Only



This software may be used \*\*ONLY\*\*:



\- In an \*\*isolated lab environment\*\* (dedicated VMs, air-gapped where possible).

\- On systems you \*\*own\*\* or have \*\*written authorization\*\* to test.

\- For \*\*educational\*\*, \*\*defensive research\*\*, or \*\*authorized penetration

&#x20; testing\*\* engagements with a signed scope document.



\## Strictly Prohibited



\- Running against any system without explicit written authorization.

\- Deploying in production or on third-party infrastructure.

\- Using for surveillance, stalking, harassment, or any illegal activity.

\- Distribution to unauthorized parties.



\## Legal Notice



Unauthorized use of this software may violate:



\- \*\*India:\*\* Information Technology Act, 2000 (Sections 43, 66, 66C, 66D, 67)

\- \*\*USA:\*\* Computer Fraud and Abuse Act (18 U.S.C. § 1030)

\- \*\*EU:\*\* Directive 2013/40/EU on attacks against information systems

\- \*\*UK:\*\* Computer Misuse Act 1990



Violations are criminal offenses and may result in imprisonment and fines.



\## Detection Signatures (Published for Defenders)



We publish these IOCs so blue teams can detect this technique:



| Type | Indicator |

|------|-----------|

| Registry | `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsSecurityUpdate` |

| Scheduled Task | `WindowsUpdateTask` |

| File | `svchost.exe` in `%TEMP%\\WindowsUpdate\_\*` |

| Process | Headless Chrome spawned by non-browser parent |

| Network | Repeated POST to `/exfil/\*` every 15s |

| Event Log | `wevtutil cl Security` / `wevtutil cl System` |



\## Contact



Guide: Dr. S. Udhayakumar  

Institution: Amrita School of Computing, Chennai Campus

