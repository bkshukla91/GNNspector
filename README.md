# 🛡️ GNNspector

> **An Advanced Graph Neural Network (GNN) based Static Application Security Testing (SAST) Tool**

GNNspector is a next-generation AI-driven static analysis tool engineered to detect vulnerabilities (such as Buffer Overflows, Command Injections, etc.) in source code. Instead of relying on traditional regular expressions (Regex), it parses source code into structured **Abstract Syntax Trees (AST)** using Tree-sitter, generates deep semantic node features via **Microsoft CodeBERT**, and utilizes a custom **Graph Neural Network (GCN)** architecture to classify files as Safe or Vulnerable.

Post-detection, it routes the telemetry to a hybrid LLM core (Cloud / Local Ollama) to generate a full remediation report and initiates an interactive security assistant patch loop directly inside your terminal.

---

## 📋 Prerequisites & Dependencies

To ensure the scanner operates correctly, your environment must satisfy the following system and software requirements:

### 1. Python Environment
- **Python 3.10 or higher** must be installed on your system.
- **Pip** (Python Package Manager) should be updated to the latest version.

### 2. Ollama & DeepSeek-Coder (Required for Local Offline Mode)
The engine utilizes **Ollama** for hosting local LLMs to guarantee data privacy during code audits.
1. **Install Ollama:** Download and install the application for your operating system from the [Official Ollama Website](https://ollama.com).
2. **Pull the DeepSeek Model:** Open your terminal or command prompt and execute the following command (this is mandatory for the offline pipeline):
   ```bash
   ollama run deepseek-coder:1.3b

### 3. System Compilation Tools (For Linux / Ubuntu Users)
PyTorch Geometric and Tree-sitter components require native C++ build architectures for dynamic parser compilation:
   ```bash 
sudo apt-get update
sudo apt-get install build-essential python3-dev

🚀 Installation & Local Setup
Follow these steps sequentially to package and install GNNspector as a global command-line utility:

Step 1: Clone the Repository
   ```bash 
git clone https://github.com/bkshukla91/GNNspector.git
cd GNNspector

Step 2: Provision Proprietary Model Weights
Since the GNN matrix structural weights are proprietary, you must supply the pre-trained neural network file manually:

Copy your trained weights file named vulnerability_gnn_model.pt.

Place it directly inside the internal gnnspector/ subdirectory.
(Note: This binary file is pre-configured in .gitignore and will never be pushed to public repositories).

Step 3: Install as a Global CLI Tool
Run the following installation wrapper from the root directory (where pyproject.toml is located):

Bash
pip install -e .
This automated routine resolves all complex math and learning frameworks (torch, torch-geometric, transformers, rich, tree-sitter-languages) and maps gnnspector to your global environment path.

Step 4: Add Environment Secrets (Optional for Cloud Integration)
For accelerated triage using cloud infrastructure, create a .env file in the root directory and declare your API credential:

Plaintext
OPENROUTER_API_KEY=your_actual_api_key_here
💻 Operational Usage
Once packaged, GNNspector can be invoked globally from any file path or terminal active location:

Bash
gnnspector path/to/your/target_code.c
⚙️ Pipeline Execution Lifecycle
Ingestion & Resolution: Target code is verified, and the corresponding programming grammar extension is loaded.

AST Decomposition: Tree-sitter builds a concrete syntax topology mapping the control flow of the file.

Semantic Featurization: Microsoft CodeBERT processes each individual code block node into a high-dimensional dense vector representation.

GNN Matrix Verdict: The PyTorch Geometric GCN layer triggers message-passing across graph vertices to evaluate security risks.

LLM Remediation Triage: The pipeline prompts Poolside AI (Cloud) or DeepSeek-Coder (Local) to compose an actionable markdown intelligence report.

Interactive Feedback Loop: An active CLI chat interface allows you to query the LLM for automated patch variations and logical fixes.

📄 License
This architecture is distributed under the MIT License - see the LICENSE file for open-source compliance details.

👨‍💻 Author: Balkrishna Shukla

🏫 Affiliation: Cyber Security Branch, Engineering College Ajmer (ECA)