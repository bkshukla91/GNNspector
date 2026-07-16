import os
import sys
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool
from torch_geometric.data import Data
from transformers import AutoTokenizer, AutoModel
import requests
import numpy as np
from dotenv import load_dotenv

# Rich UI imports
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.table import Table
from rich.markdown import Markdown

load_dotenv()
console = Console()

if os.getenv("HF_TOKEN"):
    os.environ["HF_TOKEN"] = os.getenv("HF_TOKEN")

# ==========================================
# 1. GNN Model Architecture (Exact Original)
# ==========================================
class VulnerabilityGNN(nn.Module):
    def __init__(self, input_dim=768, hidden_dim=128, num_classes=2):
        super(VulnerabilityGNN, self).__init__()
        self.conv1 = GCNConv(input_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.fc = nn.Linear(hidden_dim, num_classes)

    def forward(self, x, edge_index, batch):
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=0.2, training=self.training)
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        graph_vector = global_mean_pool(x, batch)
        logits = self.fc(graph_vector)
        return logits

# ==========================================
# 2. Universal Tree-sitter AST Graph Generator
# ==========================================
def generate_ast_graph(file_path, file_ext, source_code):
    lang_map = {
        '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
        '.java': 'java', '.c': 'c', '.cpp': 'cpp', '.html': 'html', '.css': 'css'
    }

    if file_ext not in lang_map:
        return None

    lang_name = lang_map[file_ext]
    try:
        from tree_sitter_languages import get_parser
        parser = get_parser(lang_name)
    except Exception as e:
        console.print(f"[bold red]❌ Tree-sitter core mismatch for {lang_name}: {e}[/bold red]")
        return None

    tree = parser.parse(bytes(source_code, "utf8"))
    root_node = tree.root_node

    nodes = []
    edges = []
    node_counter = 0

    def traverse_tree(node):
        nonlocal node_counter
        current_id = node_counter

        node_text = source_code[node.start_byte:node.end_byte].strip()
        if not node_text or len(node_text) > 64:
            node_text = node.type

        nodes.append({"id": current_id, "code": node_text})
        node_counter += 1

        for child in node.children:
            child_id = traverse_tree(child)
            edges.append({"source": current_id, "target": child_id})

        return current_id

    traverse_tree(root_node)
    return {"nodes": nodes, "edges": edges}

# ==========================================
# 3. Vector Embeddings Layer (CodeBERT with Live Progress)
# ==========================================
def get_embeddings_and_data(graph_data):
    if not graph_data or not graph_data["nodes"]:
        x = torch.randn(5, 768)
        edge_index = torch.tensor([[0, 1, 2, 3], [1, 2, 3, 0]], dtype=torch.long)
        return Data(x=x, edge_index=edge_index)

    tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    model = AutoModel.from_pretrained("microsoft/codebert-base", use_safetensors=True)

    node_features = []
    total_nodes = len(graph_data["nodes"])

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]CodeBERT Embeddings... Node {task.completed}/{task.total}"),
        BarColumn(bar_width=40, style="deep_sky_blue1"),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Embedding Nodes", total=total_nodes)

        for node in graph_data["nodes"]:
            inputs = tokenizer(node["code"], return_tensors="pt", truncation=True, max_length=64)
            with torch.no_grad():
                outputs = model(**inputs)
                embedding = outputs.last_hidden_state[0][0].numpy()
            node_features.append(embedding)
            progress.advance(task, 1)

    x = torch.tensor(np.array(node_features), dtype=torch.float)
    edge_list = [[e["source"], e["target"]] for e in graph_data["edges"]]
    edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous() if edge_list else torch.tensor([[], []], dtype=torch.long)
    return Data(x=x, edge_index=edge_index)

# ==========================================
# 4. Hybrid Cloud & Local LLM Auditor Engine
# ==========================================
def get_cloud_audit(raw_code, gnn_status, file_ext):
    api_key = os.getenv("OPENROUTER_API_KEY")
    url_cloud = "https://openrouter.ai/api/v1/chat/completions"
    url_local = "http://localhost:11434/api/chat"

    safe_code = raw_code.encode("ascii", "ignore").decode("ascii")
    prompt = (
        f"You are GNNspector SAST Auditor. GNN flagged code triage as: {gnn_status}.\n\n"
        f"Analyze this raw script and provide a precise vulnerability report in Markdown format with:\n"
        f"1. VULNERABILITY DETAILS & LOCATION\n"
        f"2. ROOT CAUSE & EXPLOIT MECHANICS\n"
        f"3. SECURE REWRITE PATCH (inside standard markdown code fence)\n"
        f"4. FUTURE PROACTIVE ADVICE\n\n"
        f"Target Code:\n{safe_code}"
    )

    if api_key:
        headers_cloud = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json"
        }
        payload_cloud = {
            "model": "poolside/laguna-xs-2.1",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1
        }
        try:
            console.print("[yellow][☁️] Attempting Cloud Core Audit via Poolside...[/yellow]")
            res = requests.post(url_cloud, json=payload_cloud, headers=headers_cloud, timeout=45)
            if res.status_code == 200:
                console.print("[bold green][✅] Cloud Audit Successful![/bold green]")
                return res.json()['choices'][0]['message']['content']
        except Exception as e:
            console.print(f"[orange3][⚠️] Cloud Connection Failed: {str(e)}[/orange3]")

    # Fallback to local
    console.print("[orange3][🦙] Switching to Local Offline Infrastructure...[/orange3]")
    payload_local = {
        "model": "deepseek-coder:1.3b",
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"temperature": 0.1}
    }
    try:
        res_local = requests.post(url_local, json=payload_local, timeout=90)
        if res_local.status_code == 200:
            console.print("[bold green][✅] Local Ollama Audit Successful![/bold green]")
            return res_local.json()['message']['content']
    except Exception as local_err:
        return f"❌ Critical Pipeline Failure: {str(local_err)}"

# ==========================================
# 5. Pipeline Core (For CLI & FastAPI)
# ==========================================
def run_core_pipeline(file_name, file_ext, raw_code):
    graph_data = generate_ast_graph(file_name, file_ext, raw_code)
    data = get_embeddings_and_data(graph_data)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    MODEL_PATH = os.path.join(base_dir, "vulnerability_gnn_model.pt")
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    if not os.path.exists(MODEL_PATH):
        return "🔴 VULNERABLE (Weights Not Found fallback)", 50.0, raw_code, graph_data

    model = VulnerabilityGNN(input_dim=768, hidden_dim=128, num_classes=2).to(device)
    model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
    model.eval()

    data = data.to(device)
    batch = torch.zeros(data.x.size(0), dtype=torch.long).to(device)

    with torch.no_grad():
        logits = model(data.x, data.edge_index, batch)
        prediction = logits.argmax(dim=1).item()
        probabilities = F.softmax(logits, dim=1)
        confidence = probabilities[0][prediction].item() * 100

    if prediction == 1:
        status = "🔴 VULNERABLE"
    else:
        status = "🟢 SAFE"

    return status, confidence, raw_code, graph_data

# ==========================================
# 6. Interactive CLI Chat
# ==========================================
def interactive_chat(raw_code, gnn_status, file_ext, initial_report):
    console.print(Panel.fit("[bold yellow]💬 🛡️👁️‍🗨️ GNNspector INTERACTIVE SECURITY ASSISTANT INITIATED[/bold yellow]\n[dim](Type 'exit' or 'quit' to terminate the session)[/dim]", border_style="yellow"))

    messages = [
        {"role": "system", "content": f"You are GNNspector SAST Auditor. Code Ext: {file_ext}, GNN: {gnn_status}. Code:\n{raw_code}\nInitial Report:\n{initial_report}"},
        {"role": "assistant", "content": initial_report}
    ]

    while True:
        try:
            user_query = console.input("\n[bold green][🧑 User] > [/bold green]").strip()
            if not user_query: continue
            if user_query.lower() in ['exit', 'quit']:
                console.print("[bold red]Session Terminated. Stay Secure![/bold red]")
                break

            messages.append({"role": "user", "content": user_query})

            with console.status("[bold cyan]GNNspector Engine thinking..."):
                response_content = ""
                api_key = os.getenv("OPENROUTER_API_KEY")
                if api_key:
                    try:
                        res = requests.post("https://openrouter.ai/api/v1/chat/completions", json={"model": "poolside/laguna-xs-2.1", "messages": messages}, headers={"Authorization": f"Bearer {api_key.strip()}"}, timeout=45)
                        if res.status_code == 200: response_content = res.json()['choices'][0]['message']['content']
                    except Exception: pass

                if not response_content:
                    try:
                        res_local = requests.post("http://localhost:11434/api/chat", json={"model": "deepseek-coder:1.3b", "messages": messages, "stream": False}, timeout=90)
                        if res_local.status_code == 200: response_content = res_local.json()['message']['content']
                    except Exception: response_content = "❌ Offline/Online Core pipeline failed."

            console.print(Panel(Markdown(response_content), title="[bold cyan]🤖 GNNspector Response[/bold cyan]", border_style="cyan"))
            messages.append({"role": "assistant", "content": response_content})
        except KeyboardInterrupt:
            break

# ==========================================
# 7. Main Execution Entry for CLI
# ==========================================
def main():
    if len(sys.argv) < 2:
        console.print("[bold red]Usage: gnnspector <path_to_file>[/bold red]")
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        console.print(f"[bold red]❌ File {file_path} not found.[/bold red]")
        sys.exit(1)

    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    # 💡 LOGO & UPDATED PANEL
    console.print(Panel(f"[bold cyan]🔍 Target Detected:[/bold cyan] {os.path.basename(file_path)}\n[bold cyan]📁 System Type:[/bold cyan] {ext}", title="🛡️👁️‍🗨️ GNNspector : GNN based SAST Engine", border_style="blue"))

    with open(file_path, 'r', encoding='utf-8') as f:
        raw_code = f.read()

    with Progress(SpinnerColumn(), TextColumn("[bold yellow]{task.description}"), console=console) as progress:
        t1 = progress.add_task("[1/3] Parsing source code structure into AST Graph...", total=1)
        status, confidence, _, graph_data = run_core_pipeline(file_path, ext, raw_code)
        progress.advance(t1, 1)

    table = Table(title="AST Structure Metrics", border_style="dim")
    table.add_column("Component", style="cyan")
    table.add_column("Count", style="magenta")
    table.add_row("Nodes", str(len(graph_data["nodes"])))
    table.add_row("Edges", str(len(graph_data["edges"])))
    console.print(table)

    style = "red" if "VULNERABLE" in status else "green"
    console.print(Panel(f"[bold {style}]RESULT: {status} (GNN Confidence: {confidence:.2f}%)[/bold {style}]", title="GNN Decision Layer", border_style=style))

    report = get_cloud_audit(raw_code, f"{status} (Confidence: {confidence:.2f}%)", ext)
    console.print(Panel(Markdown(report), title="🛡️ GNNspector Deep Security Audit Report", border_style="purple"))

    interactive_chat(raw_code, status, ext, report)

if __name__ == "__main__":
    main()
