"""Synthetic employee profiles — 10 people across 5 departments."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    email: str
    name: str
    department: str
    hostname: str
    usual_ip: str
    usual_country: str
    device: str
    groups: tuple[str, ...]


# Two employees per department: Engineering, Finance, HR, DevOps, Sales.
PROFILES: tuple[Profile, ...] = (
    Profile(
        "ava.eng@acmecorp.com",
        "Ava Reyes",
        "Engineering",
        "LAPTOP-ENG-01",
        "103.21.48.20",
        "IN",
        "MacBook-Ava",
        ("Eng-All", "GitHub-Org"),
    ),
    Profile(
        "liam.eng@acmecorp.com",
        "Liam Wong",
        "Engineering",
        "LAPTOP-ENG-02",
        "103.21.48.21",
        "IN",
        "LAPTOP-ENG-02",
        ("Eng-All", "GitHub-Org"),
    ),
    Profile(
        "bob.finance@acmecorp.com",
        "Bob Sharma",
        "Finance",
        "LAPTOP-FINANCE-03",
        "103.21.48.11",
        "IN",
        "LAPTOP-FINANCE-03",
        ("Finance-All", "SAP-Users", "Sensitive-Finance"),
    ),
    Profile(
        "mia.finance@acmecorp.com",
        "Mia Khan",
        "Finance",
        "LAPTOP-FINANCE-04",
        "103.21.48.12",
        "IN",
        "LAPTOP-FINANCE-04",
        ("Finance-All", "SAP-Users"),
    ),
    Profile(
        "alice.hr@acmecorp.com",
        "Alice Chen",
        "Human Resources",
        "LAPTOP-HR-03",
        "103.21.48.10",
        "IN",
        "MacBook-Alice",
        ("HR-All", "Workday-Users"),
    ),
    Profile(
        "noah.hr@acmecorp.com",
        "Noah Patel",
        "Human Resources",
        "LAPTOP-HR-05",
        "103.21.48.13",
        "IN",
        "LAPTOP-HR-05",
        ("HR-All", "Workday-Users"),
    ),
    Profile(
        "charlie.devops@acmecorp.com",
        "Charlie Patel",
        "DevOps",
        "LAPTOP-DEVOPS-01",
        "103.21.48.14",
        "IN",
        "MacBook-Charlie",
        ("DevOps-All", "AWS-Admins"),
    ),
    Profile(
        "ella.devops@acmecorp.com",
        "Ella Gupta",
        "DevOps",
        "LAPTOP-DEVOPS-02",
        "103.21.48.15",
        "IN",
        "LAPTOP-DEVOPS-02",
        ("DevOps-All", "AWS-Admins"),
    ),
    Profile(
        "raj.sales@acmecorp.com",
        "Raj Mehta",
        "Sales",
        "LAPTOP-SALES-01",
        "103.21.48.16",
        "IN",
        "LAPTOP-SALES-01",
        ("Sales-All", "Salesforce-Users"),
    ),
    Profile(
        "zoe.sales@acmecorp.com",
        "Zoe Diaz",
        "Sales",
        "LAPTOP-SALES-02",
        "103.21.48.17",
        "IN",
        "LAPTOP-SALES-02",
        ("Sales-All", "Salesforce-Users"),
    ),
)

DEPARTMENTS = ("Engineering", "Finance", "Human Resources", "DevOps", "Sales")
