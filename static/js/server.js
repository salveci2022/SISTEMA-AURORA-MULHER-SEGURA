const express = require('express');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'segredo-mulher-segura',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // em produção, use true se tiver HTTPS
}));

// Middleware de autenticação
const requireLogin = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/panel/login');
    }
    next();
};

// Rota principal (página inicial)
app.get('/', (req, res) => {
    res.send(`
        <html>
            <head>
                <title>Aurora Mulher Segura</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                    h1 { color: #764ba2; }
                    a { display: inline-block; margin: 20px; padding: 15px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; }
                </style>
            </head>
            <body>
                <h1>Bem-vindo ao Sistema Aurora Mulher Segura</h1>
                <p>Esta é a página inicial do sistema.</p>
                <a href="/panel/login">Acessar Painel Administrativo</a>
            </body>
        </html>
    `);
});

// Rota de login (GET)
app.get('/panel/login', (req, res) => {
    if (req.session.user) {
        return res.redirect('/panel/dashboard');
    }
    res.send(`
        <html>
            <head>
                <title>Login Administrador</title>
                <style>
                    body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; justify-content: center; align-items: center; height: 100vh; }
                    .login-container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 20px rgba(0,0,0,0.2); width: 100%; max-width: 400px; }
                    h1 { text-align: center; color: #333; margin-bottom: 30px; }
                    label { display: block; margin-bottom: 8px; color: #555; }
                    input { width: 100%; padding: 12px; margin-bottom: 20px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
                    button { width: 100%; padding: 12px; background: linear-gradient(to right, #667eea, #764ba2); border: none; border-radius: 5px; color: white; font-size: 16px; cursor: pointer; }
                    button:hover { opacity: 0.9; }
                    .error { color: red; margin-top: 10px; text-align: center; }
                </style>
            </head>
            <body>
                <div class="login-container">
                    <h1>Login Administrador</h1>
                    <form method="POST" action="/panel/login">
                        <div>
                            <label for="usuario">Usuário</label>
                            <input type="text" id="usuario" name="usuario" required>
                        </div>
                        <div>
                            <label for="senha">Senha</label>
                            <input type="password" id="senha" name="senha" required>
                        </div>
                        <button type="submit">Entrar</button>
                    </form>
                    <div class="error">
                        ${req.query.error ? 'Credenciais inválidas!' : ''}
                    </div>
                </div>
            </body>
        </html>
    `);
});

// Rota de login (POST)
app.post('/panel/login', (req, res) => {
    const { usuario, senha } = req.body;
    // Aqui você deve verificar no banco de dados. Para demonstração, usamos credenciais fixas.
    if (usuario === 'admin' && senha === 'admin123') {
        req.session.user = { usuario, role: 'admin' };
        return res.redirect('/panel/dashboard');
    } else {
        return res.redirect('/panel/login?error=1');
    }
});

// Rota de logout
app.get('/panel/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/panel/login');
});

// Dashboard (após login)
app.get('/panel/dashboard', requireLogin, (req, res) => {
    res.send(`
        <html>
            <head>
                <title>Dashboard</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; }
                    .navbar { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 20px; display: flex; justify-content: space-between; }
                    .sidebar { width: 250px; background: #f8f9fa; height: 100vh; position: fixed; padding: 20px; box-shadow: 2px 0 5px rgba(0,0,0,0.1); }
                    .content { margin-left: 250px; padding: 20px; }
                    .menu-item { padding: 12px; margin: 5px 0; border-radius: 5px; cursor: pointer; transition: 0.3s; }
                    .menu-item:hover { background: #e9ecef; }
                    .card { background: white; padding: 20px; border-radius: 10px; margin: 15px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                    .btn-panico { background: #e74c3c; color: white; border: none; padding: 15px 25px; border-radius: 50px; font-size: 16px; cursor: pointer; position: fixed; bottom: 20px; right: 20px; }
                    a { text-decoration: none; color: inherit; }
                </style>
            </head>
            <body>
                <div class="navbar">
                    <h1>🛡️ Aurora Mulher Segura - Painel</h1>
                    <div>Administrador (${req.session.user.usuario})</div>
                </div>
                
                <div class="sidebar">
                    <h3>Menu</h3>
                    <div class="menu-item"><a href="/panel/dashboard">📊 Dashboard</a></div>
                    <div class="menu-item"><a href="/panel/usuarias">👥 Lista de Usuárias</a></div>
                    <div class="menu-item"><a href="/panel/relatorios">📈 Relatórios</a></div>
                    <div class="menu-item"><a href="/panel/mensagens">✉️ Mensagens/Alertas</a></div>
                    <div class="menu-item"><a href="/panel/configuracoes">⚙️ Configurações</a></div>
                    <div class="menu-item"><a href="/panel/historico">📜 Histórico de atividades</a></div>
                    <div class="menu-item"><a href="/panel/perfil">👤 Perfil do administrador</a></div>
                    <div class="menu-item"><a href="/panel/cadastrar">➕ Cadastrar nova usuária</a></div>
                    <div class="menu-item"><a href="/panel/exportar">📤 Exportar dados</a></div>
                    <div class="menu-item"><a href="/panel/logout">🚪 Sair/Logout</a></div>
                </div>
                
                <div class="content">
                    <div class="card">
                        <h2>Bem-vindo ao Painel Administrativo</h2>
                        <p>Esta é a página de dashboard. Aqui você pode ver um resumo das atividades do sistema.</p>
                    </div>
                    
                    <div class="card">
                        <h3>📋 Resumo do Sistema</h3>
                        <p>• Usuárias cadastradas: 0</p>
                        <p>• Alertas ativos: 0</p>
                        <p>• Mensagens não lidas: 0</p>
                    </div>
                </div>
                
                <button class="btn-panico" onclick="alert('Botão de Pânico Ativado! Enviando alerta...')">🚨 Botão de Pânico</button>
            </body>
        </html>
    `);
});

// Rota para a lista de usuárias
app.get('/panel/usuarias', requireLogin, (req, res) => {
    res.send(`
        <html>
            <head>
                <title>Lista de Usuárias</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; }
                    .navbar { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 20px; display: flex; justify-content: space-between; }
                    .sidebar { width: 250px; background: #f8f9fa; height: 100vh; position: fixed; padding: 20px; box-shadow: 2px 0 5px rgba(0,0,0,0.1); }
                    .content { margin-left: 250px; padding: 20px; }
                    .menu-item { padding: 12px; margin: 5px 0; border-radius: 5px; cursor: pointer; transition: 0.3s; }
                    .menu-item:hover { background: #e9ecef; }
                    .card { background: white; padding: 20px; border-radius: 10px; margin: 15px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                    a { text-decoration: none; color: inherit; }
                </style>
            </head>
            <body>
                <div class="navbar">
                    <h1>🛡️ Aurora Mulher Segura - Painel</h1>
                    <div>Administrador (${req.session.user.usuario})</div>
                </div>
                
                <div class="sidebar">
                    <h3>Menu</h3>
                    <div class="menu-item"><a href="/panel/dashboard">📊 Dashboard</a></div>
                    <div class="menu-item"><a href="/panel/usuarias">👥 Lista de Usuárias</a></div>
                    <div class="menu-item"><a href="/panel/relatorios">📈 Relatórios</a></div>
                    <div class="menu-item"><a href="/panel/mensagens">✉️ Mensagens/Alertas</a></div>
                    <div class="menu-item"><a href="/panel/configuracoes">⚙️ Configurações</a></div>
                    <div class="menu-item"><a href="/panel/historico">📜 Histórico de atividades</a></div>
                    <div class="menu-item"><a href="/panel/perfil">👤 Perfil do administrador</a></div>
                    <div class="menu-item"><a href="/panel/cadastrar">➕ Cadastrar nova usuária</a></div>
                    <div class="menu-item"><a href="/panel/exportar">📤 Exportar dados</a></div>
                    <div class="menu-item"><a href="/panel/logout">🚪 Sair/Logout</a></div>
                </div>
                
                <div class="content">
                    <div class="card">
                        <h2>👥 Lista de Usuárias</h2>
                        <p>Aqui você pode gerenciar as usuárias do sistema.</p>
                        <ul>
                            <li>Usuária 1</li>
                            <li>Usuária 2</li>
                            <li>Usuária 3</li>
                        </ul>
                    </div>
                </div>
            </body>
        </html>
    `);
});

// Rota para relatórios
app.get('/panel/relatorios', requireLogin, (req, res) => {
    res.send(`
        <html>
            <head>
                <title>Relatórios</title>
                <!-- Estilos similares aos anteriores -->
            </head>
            <body>
                <div class="navbar">...</div>
                <div class="sidebar">...</div>
                <div class="content">
                    <div class="card">
                        <h2>📈 Relatórios</h2>
                        <p>Página de relatórios em construção.</p>
                    </div>
                </div>
            </body>
        </html>
    `);
});

// Adicione rotas semelhantes para as outras páginas (mensagens, configurações, histórico, perfil, cadastrar, exportar)

// Rota genérica para as páginas não implementadas (apenas para mostrar que existe)
const pages = [
    'mensagens',
    'configuracoes',
    'historico',
    'perfil',
    'cadastrar',
    'exportar'
];

pages.forEach(page => {
    app.get(`/panel/${page}`, requireLogin, (req, res) => {
        res.send(`
            <html>
                <head>
                    <title>${page.charAt(0).toUpperCase() + page.slice(1)}</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; }
                        .navbar { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 20px; display: flex; justify-content: space-between; }
                        .sidebar { width: 250px; background: #f8f9fa; height: 100vh; position: fixed; padding: 20px; box-shadow: 2px 0 5px rgba(0,0,0,0.1); }
                        .content { margin-left: 250px; padding: 20px; }
                        .menu-item { padding: 12px; margin: 5px 0; border-radius: 5px; cursor: pointer; transition: 0.3s; }
                        .menu-item:hover { background: #e9ecef; }
                        .card { background: white; padding: 20px; border-radius: 10px; margin: 15px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                        a { text-decoration: none; color: inherit; }
                    </style>
                </head>
                <body>
                    <div class="navbar">
                        <h1>🛡️ Aurora Mulher Segura - Painel</h1>
                        <div>Administrador (${req.session.user.usuario})</div>
                    </div>
                    
                    <div class="sidebar">
                        <h3>Menu</h3>
                        <div class="menu-item"><a href="/panel/dashboard">📊 Dashboard</a></div>
                        <div class="menu-item"><a href="/panel/usuarias">👥 Lista de Usuárias</a></div>
                        <div class="menu-item"><a href="/panel/relatorios">📈 Relatórios</a></div>
                        <div class="menu-item"><a href="/panel/mensagens">✉️ Mensagens/Alertas</a></div>
                        <div class="menu-item"><a href="/panel/configuracoes">⚙️ Configurações</a></div>
                        <div class="menu-item"><a href="/panel/historico">📜 Histórico de atividades</a></div>
                        <div class="menu-item"><a href="/panel/perfil">👤 Perfil do administrador</a></div>
                        <div class="menu-item"><a href="/panel/cadastrar">➕ Cadastrar nova usuária</a></div>
                        <div class="menu-item"><a href="/panel/exportar">📤 Exportar dados</a></div>
                        <div class="menu-item"><a href="/panel/logout">🚪 Sair/Logout</a></div>
                    </div>
                    
                    <div class="content">
                        <div class="card">
                            <h2>${page.charAt(0).toUpperCase() + page.slice(1)}</h2>
                            <p>Página ${page} em construção.</p>
                        </div>
                    </div>
                </body>
            </html>
        `);
    });
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
    console.log(`Acesse: http://localhost:${PORT}`);
});