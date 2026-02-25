# AD User Automation Portal 🔐

Uma aplicação Web moderna construída em Python/Flask para automatizar a criação de usuários no Active Directory, projetada para delegar tarefas de administração de forma segura e visualmente intuitiva.

![Design Preview](https://github.com/hroliveira/CreateUserAD/raw/main/static/img/preview.png) *(Nota: Adicione uma imagem real aqui posteriormente)*

## ✨ Funcionalidades

- **Autenticação AD**: Logon obrigatório para administradores/suportes utilizando credenciais de domínio.
- **Design Moderno**: Interface "Dark Cyan" inspirada nos consoles clássicos do AD com estética cyberpunk.
- **Criação Simplificada**: Formulário otimizado para preenchimento rápido de novos usuários.
- **Perfis Pré-configurados**: Atribuição automática de OUs e Grupos baseada no cargo selecionado (Comercial, Jurídico, TI, etc).
- **Segurança**: Suporte a conexões LDAPS (porta 636) e tratamento seguro de senhas via Unicode.
- **Logs de Auditoria**: Registro detalhado de todas as operações de criação para rastreabilidade.

## 🚀 Como Executar

### 1. Pré-requisitos
- Python 3.8+
- Acesso de rede ao servidor AD (LDAP/LDAPS)

### 2. Instalação
Clone o repositório e instale as dependências:
```bash
git clone https://github.com/hroliveira/CreateUserAD.git
cd CreateUserAD
python -m venv .venv
source .venv/bin/activate  # No Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configuração
Crie seu arquivo `.env` baseado no exemplo fornecido:
```bash
cp .env.example .env
```
Edite o `.env` com suas credenciais de servidor e bind.

### 4. Execução
```bash
python app.py
```
Acesse em: `http://localhost:5000`

## 🛠️ Tecnologias Utilizadas

- **Backend**: Python / Flask
- **AD Logic**: `ldap3`
- **Frontend**: Bootstrap 5 + Vanilla CSS (Customizado)
- **Segurança**: `python-dotenv` para variáveis de ambiente

## 📝 Licença
Este projeto é para uso interno e educacional.
