# ai-migration-assessment-tool-v2
AI-Powered Migration Assessment Tool

The AI-Powered Migration Assessment Tool is a command-line application designed to create a "Digital Twin" of an IT infrastructure. It performs deep discovery of virtual and physical servers, stores the collected data in a structured database, and provides a foundation for intelligent analysis and migration planning.

The tool is built to be resilient, secure, and extensible, featuring a robust, resumable workflow that can recover from interruptions and track the full history of each discovery run.
Key Features

    Modular Discovery Agents: Pluggable agents for different environments (VMware vSphere, Linux, Windows).

    Resumable & Audited Runs: Automatically saves progress after every task. Failed or interrupted runs can be resumed from the exact point of failure, and each run is tracked with a unique ID for a full audit trail.

    Secure Credential Storage: Integrates with the system's native keyring (macOS Keychain, Windows Credential Manager) to ensure no plaintext passwords are ever stored.

    Configuration-Driven: A central knowledge_base.yaml file defines the discovery tasks and agent settings, allowing for easy extension without changing the core code.

    Two-Phase Operation: A clear separation between data collection (ingest) and data analysis (profile).

    Optional Graph Export: Discovered infrastructure data can be exported to a Neo4j graph database to visualize complex relationships and dependencies.

Project Flow

The tool operates in a series of clear, sequential steps.

    Setup & Configuration:

        The user installs the required Python packages.

        The inventory.csv file is populated with the target servers to be discovered.

        The knowledge_base.yaml is configured with the specific discovery tasks for each OS type.

    Store Credentials:

        The user runs the setup_credentials.py script.

        The script reads the inventory.csv to find all unique usernames.

        It securely prompts for a password for each user and stores it in the system's native keyring.

    Phase 1: Data Ingestion (ingest command):

        When the ingest command is run for the first time, a new run is created in the database with a unique run_id.

        The tool reads the inventory and populates the database with a checklist of all tasks required for this run, as defined in knowledge_base.yaml.

        The DataIngestionAgent queries the database for pending tasks for the current run_id.

        It dispatches tasks to the appropriate discovery agents (e.g., VsphereDiscovery).

        As each granular task (e.g., discovering clusters, then hosts, then VMs) completes, its status is updated in the database.

        If the process is interrupted, it can be restarted using the --resume-run <ID> flag to continue exactly where it left off.

    Phase 2: Analysis & Profiling (profile command):

        Once ingestion is complete, the profile command is run.

        The ProfilingAgent reads the collected data from the SQLite database.

        It performs analysis to build relationships and identify dependencies (this is where future AI/ML logic would be integrated).

        Optionally, the processed data can be exported to a Neo4j database for visualization.

Prerequisites

    Python 3.12+

    A system keyring backend (e.g., secretstorage on Linux, or the built-in credential managers on Windows/macOS).

Setup Instructions

    Clone the Repository:

    git clone <your-repo-url>
    cd ai-migration-assessment-tool-v2

    Create and Activate a Virtual Environment:

    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate

    Install Dependencies:

    pip install -r requirements.txt

Configuration

    inventory.csv:
    Populate this file with the servers you want to discover. The following columns are required:

        hostname: The IP address or FQDN of the target.

        os_type: The agent to use (e.g., vsphere, linux, windows).

        user: The username required to connect to the host.

    Example:

    hostname,os_type,user
    10.10.1.5,vsphere,read_only@vsphere.local
    webapp01.prod.local,linux,ssh_user

    knowledge_base.yaml:
    This file drives the discovery process. Ensure the tasks_per_os section is defined with the tasks you want to run for each os_type. The task names must match the method names in the corresponding discovery agent.

    Example tasks_per_os section:

    tasks_per_os:
      vsphere:
        - clusters
        - hosts
        - datastores
        - vms
      linux:
        - system_info
        - running_processes

Usage

Run all commands from the root directory of the project.

    Store Credentials (Run Once):
    This will securely prompt you for the passwords for the users listed in your inventory.

    python -m src.setup_credentials

    Run a New Data Ingestion:
    This starts a fresh discovery run. Take note of the run_id that is created.

    python -m src.main ingest

    Resume a Failed/Interrupted Run:
    If a run is interrupted, use the run_id to continue where you left off.

    python -m src.main ingest --resume-run <ID>

    Run the Analysis & Profiling Phase:
    Once ingestion is complete, run the profiling command.

    python -m src.main profile

    Export to Neo4j (Optional):
    To also export the data to a graph database, use the --export-neo4j flag.

    python -m src.main profile --export-neo4j

Project File Structure

ai-migration-assessment-tool-v2/
├── data/
│   ├── assessment.log
│   └── assessment_history.db
├── src/
│   ├── agents/
│   │   ├── agent_data_ingestion.py
│   │   ├── agent_profiling.py
│   │   ├── linux_discovery.py
│   │   ├── vsphere_discovery.py
│   │   └── windows_discovery.py
│   ├── db/
│   │   ├── db_manager.py
│   │   └── sql/
│   │       ├── insert/
│   │       ├── schema/
│   │       └── select/
│   ├── logging/
│   │   └── logger.py
│   └── main.py
├── inventory.csv
├── knowledge_base.yaml
├── requirements.txt
└── setup_credentials.py

