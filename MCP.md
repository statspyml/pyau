# pyvulscan MCP Server

Servidor MCP (Model Context Protocol) para integração do pyvulscan com o Claude Code.

## O que é MCP?

O Model Context Protocol permite que o Claude Code se conecte a ferramentas externas, expandindo suas capacidades. Com o pyvulscan MCP, o Claude pode escanear vulnerabilidades em projetos Python diretamente.

## Instalação

### Opção 1: Instalação Global (Recomendada para desenvolvimento)

```bash
# Usando pip
pip install pyvulscan[mcp]

# Usando pipx (recomendado para ferramentas CLI)
pipx install pyvulscan[mcp]

# Usando uv
uv tool install pyvulscan[mcp]
```

### Opção 2: Usando uvx (Sem Instalação - Recomendada para usuários finais)

Não requer instalação prévia. Configure diretamente no Claude Code (veja abaixo).

## Configuração no Claude Code

Existem duas formas de configurar o MCP, dependendo de como você usa o Claude Code:

### Claude Code CLI (Terminal)

Se você usa o Claude Code via terminal (comando `claude`):

**Opção 1: Arquivo .mcp.json no projeto (Recomendado)**

Crie um arquivo `.mcp.json` na raiz do seu projeto:

```json
{
  "mcpServers": {
    "pyvulscan": {
      "command": "pyvulscan-mcp"
    }
  }
}
```

**Opção 2: Comando global**

```bash
claude mcp add pyvulscan pyvulscan-mcp
```

### Claude Code Desktop (Aplicativo)

Se você usa o aplicativo Claude Code Desktop:

**macOS/Linux:**

Edite `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "pyvulscan": {
      "command": "pyvulscan-mcp"
    }
  }
}
```

**Windows:**

Edite `%APPDATA%\Claude\claude_desktop_config.json` com o mesmo conteúdo acima.

### Configuração com uvx (sem instalação)

Se preferir não instalar globalmente, use:

```json
{
  "mcpServers": {
    "pyvulscan": {
      "command": "uvx",
      "args": ["--from", "pyvulscan[mcp]", "pyvulscan-mcp"]
    }
  }
}
```

## Reiniciar o Claude Code

Após a configuração, reinicie o Claude Code para que as mudanças tenham efeito.

## Ferramentas Disponíveis

O servidor MCP expõe 3 ferramentas:

### 1. scan_vulnerabilities

Escaneia um arquivo específico de dependências para vulnerabilidades conhecidas.

**Arquivos suportados:**
- `requirements.txt`
- `poetry.lock`
- `uv.lock`
- `pyproject.toml`

**Parâmetros:**
- `file_path` (obrigatório): Caminho para o arquivo de dependências
- `groups` (opcional): Lista de grupos Poetry para auditar (ex: ["main", "dev"])
- `direct_only` (opcional): Apenas dependências diretas (requer pyproject.toml)

**Exemplo de uso no Claude Code:**

```
Escaneie vulnerabilidades no arquivo requirements.txt do meu projeto
```

### 2. scan_directory

Escaneia um diretório procurando arquivos de dependências e verifica vulnerabilidades em todos eles.

**Parâmetros:**
- `directory_path` (opcional): Caminho do diretório (padrão: diretório atual)
- `groups` (opcional): Lista de grupos Poetry para auditar
- `direct_only` (opcional): Apenas dependências diretas

**Exemplo de uso no Claude Code:**

```
Escaneie meu projeto atual para vulnerabilidades
```

### 3. check_package

Verifica vulnerabilidades em um pacote específico. Se a versão não for fornecida, o tool detecta automaticamente a versão instalada no projeto lendo os arquivos de dependências (uv.lock, poetry.lock, requirements.txt ou pyproject.toml).

**Parâmetros:**
- `package_name` (obrigatório): Nome do pacote Python (ex: "django")
- `version` (opcional): Versão para verificar (ex: "3.2.0"). Se omitido, detecta automaticamente do projeto
- `directory` (opcional): Diretório para buscar arquivos de dependências (padrão: diretório atual)

**Exemplos de uso no Claude Code:**

```
# Detecta automaticamente a versão do projeto
Verifique se o pacote requests tem vulnerabilidades

# Especifica uma versão manualmente
Verifique se o pacote django versão 3.2.0 tem vulnerabilidades
```

## Exemplos de Uso

### Escanear projeto atual

```
Claude, escaneie vulnerabilidades no meu projeto Python
```

### Verificar pacote específico

```
# Detecta automaticamente a versão instalada no projeto
Verifique se o pacote requests tem vulnerabilidades

# Ou especifica uma versão manualmente
Verifique se requests 2.25.0 tem vulnerabilidades conhecidas
```

### Escanear arquivo específico

```
Analise o arquivo requirements.txt na pasta /path/to/project
```

## Formato de Resposta

As ferramentas retornam JSON com:

```json
{
  "success": true,
  "packages_scanned": 10,
  "vulnerabilities_found": 2,
  "findings": [
    {
      "package": "django",
      "version": "3.2.0",
      "vuln_id": "GHSA-xxxx-xxxx-xxxx",
      "aliases": ["CVE-2023-12345"],
      "summary": "Description of the vulnerability",
      "severity": {
        "score": 7.5,
        "label": "HIGH",
        "type": "CVSS:3.1"
      },
      "fixed_versions": ["3.2.19", "4.1.8"]
    }
  ]
}
```

## Troubleshooting

### Servidor MCP não aparece

1. Verifique se o arquivo de configuração está correto
2. Reinicie o Claude Code completamente
3. Verifique se a instalação foi bem-sucedida: `pyvulscan-mcp --help`

### Erro de comando não encontrado

Se usar configuração com instalação global e ver erro "command not found":
- Verifique se o pacote está instalado: `pip list | grep pyvulscan`
- Tente reinstalar: `pip install --force-reinstall pyvulscan[mcp]`
- Use a opção com uvx (não requer instalação)

### Verificar logs

O Claude Code mantém logs dos servidores MCP em:
- macOS: `~/.config/claude/logs/`
- Windows: `%APPDATA%\Claude\logs\`

## Desenvolvimento

Para desenvolver o servidor MCP localmente:

```bash
# Clone o repositório
git clone https://github.com/statspyml/pyau.git
cd pyau

# Instale em modo desenvolvimento com uv
uv sync --extra mcp

# Configure o Claude Code para usar o servidor local
# Edite ~/.config/claude/claude_desktop_config.json e use o caminho completo:
# "command": "/caminho/completo/.venv/bin/pyvulscan-mcp"
```

## API OSV

O pyvulscan usa a API do [OSV (Open Source Vulnerabilities)](https://osv.dev/) para obter informações sobre vulnerabilidades conhecidas.

## Licença

MIT License - veja o arquivo LICENSE para detalhes.
