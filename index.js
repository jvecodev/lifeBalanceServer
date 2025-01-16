import express from 'express';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';



app.get('/', function (req, res) {
    res.send('Hello World')
  })




dotenv.config(); 

const app = express();
app.use(express.json()); 
app.use(express.static('./pages'));


const DATABASE_URL = process.env.DATABASE_URL;

async function verificarConexao() {
    try {
        const connection = await mysql.createConnection(DATABASE_URL);
        await connection.query('SELECT 1');  
        console.log('Conexão bem-sucedida ao banco de dados!');
        return connection;
    } catch (err) {
        console.error('Erro ao conectar ao banco de dados:', err);
        process.exit(1); 
    }
}

const connection = await verificarConexao(); 


function autenticarToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token não fornecido ou malformado' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Erro ao verificar token:', error);
        return res.status(403).json({ error: 'Token inválido' });
    }
}



app.get('/api/perfil', async (req, res) => {
    try {
        const query = 'SELECT nome, email FROM Usuario ORDER BY id_usuario DESC LIMIT 1';
        const [results] = await connection.query(query);

        if (results.length === 0) {
            return res.status(404).json({ message: 'Nenhum usuário encontrado' });
        }

        res.status(200).json({ usuario: results[0] });
    } catch (err) {
        console.error('Erro ao buscar usuário:', err);
        return res.status(500).json({ message: 'Erro ao buscar usuário' });
    }
});


app.delete('/api/perfil', autenticarToken, async (req, res) => {
    try {
        console.log('Usuário autenticado para exclusão:', req.user);
        // Consulta para deletar o usuário baseado no ID
        const [resultado] = await connection.query(
            'DELETE FROM Usuario WHERE id_usuario = ?',
            [req.user.id_usuario]
        );
        if (resultado.affectedRows > 0) {
            return res.json({ message: 'Usuário deletado com sucesso' });
        } else {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }
    } catch (error) {
        console.error('Erro ao deletar usuário:', error);
        return res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

app.put('/api/perfil', autenticarToken, async (req, res) => {
    console.log('Dados recebidos no PUT:', req.body);
    console.log('Usuário autenticado:', req.user);

    try {
        const { nome, email, senha } = req.body;


        if (!senha) {
            const [usuarioAtualizado] = await connection.query(
                'UPDATE Usuario SET nome = ?, email = ? WHERE id_usuario = ?',
                [nome, email, req.user.id_usuario]
            );

            if (usuarioAtualizado.affectedRows > 0) {
                return res.json({ message: 'Usuário atualizado com sucesso' });
            } else {
                return res.status(400).json({ error: 'Usuário não encontrado ou não atualizado' });
            }
        }


        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(senha, saltRounds);

        const [senhaAtualizada] = await connection.query(
            'UPDATE Usuario SET senha = ? WHERE id_usuario = ?',
            [hashedPassword, req.user.id_usuario]
        );

        if (senhaAtualizada.affectedRows > 0) {
            return res.json({ message: 'Senha atualizada com sucesso' });
        } else {
            return res.status(400).json({ error: 'Erro ao atualizar a senha' });
        }
    } catch (error) {
        console.error('Erro ao atualizar usuário:', error);
        return res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

    

app.get('/api/cadastrar', async (req, res) => {
    const query = 'SELECT nome FROM Usuario ORDER BY id_usuario DESC LIMIT 1'; 
    try {
        const [results] = await connection.query(query);
        if (results.length === 0) {
            return res.status(404).json({ message: 'Nenhum usuário encontrado' });
        }
        res.status(200).json({ nome: results[0].nome });
    } catch (error) {
        console.error('Erro ao buscar usuário:', error);
        res.status(500).json({ message: 'Erro ao buscar usuário' });
    }
});



app.post('/api/cadastrar', async (req, res) => {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
        return res.status(400).json({ message: 'Todos os campos são obrigatórios' });
    }

    try {
        const hashedPassword = bcrypt.hashSync(senha, 10);

        const query = 'INSERT INTO Usuario (nome, email, senha) VALUES (?, ?, ?)';
        await connection.query(query, [nome, email, hashedPassword]);

        res.status(201).json({ message: 'Usuário cadastrado com sucesso' });
    } catch (err) {
        console.error('Erro ao cadastrar usuário:', err);
        res.status(500).json({ message: 'Erro ao cadastrar usuário', error: err });
    }
});


app.post('/api/login', async (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).json({ message: 'Preencha todos os campos' });
    }

    try {
        const query = 'SELECT * FROM Usuario WHERE email = ?';
        const [results] = await connection.query(query, [email]);

        if (results.length === 0) {
            return res.status(401).json({ message: 'Email ou senha incorretos' });
        }

        const usuario = results[0];

        if (!bcrypt.compareSync(senha, usuario.senha)) {
            return res.status(401).json({ message: 'Email ou senha incorretos' });
        }

        const token = jwt.sign({ id_usuario: usuario.id_usuario, nome: usuario.nome }, process.env.JWT_SECRET, { expiresIn: '30d' });

        res.status(200).json({ message: 'Login bem-sucedido', token });
    } catch (err) {
        console.error('Erro ao verificar usuário:', err);
        res.status(500).json({ message: 'Erro ao verificar usuário' });
    }
});

app.post('/api/metas', autenticarToken, async (req, res) => {
    const { descricao, data_criacao } = req.body;

    if (!descricao || !data_criacao) {
        return res.status(400).json({ message: 'Por favor, insira uma meta válida' });
    }

    try {
        const query = 'INSERT INTO Metas (id_usuario, descricao, data_criacao) VALUES (?, ?, ?)';
        await connection.query(query, [req.user.id_usuario, descricao, data_criacao]);

        res.status(201).json({ message: 'Meta registrada com sucesso' });
    } catch (error) {
        console.error('Erro ao registrar meta:', error);
        res.status(500).json({ message: 'Erro ao registrar meta' });
    }


});

app.get('/api/metas', autenticarToken, async (req, res) => {
    try {
        const query = 'SELECT * FROM Metas WHERE id_usuario = ?';
        const [metas] = await connection.query(query, [req.user.id_usuario]);

        if (metas.length === 0) {
            return res.status(404).json({ message: 'Nenhuma meta encontrada' });
        }

        res.status(200).json({ metas });
    } catch (error) {
        console.error('Erro ao buscar metas:', error);
        res.status(500).json({ message: 'Erro ao buscar metas' });
    }
});

app.delete('/api/metas/:id_meta', autenticarToken, async (req, res) => {
    const { id_meta } = req.params;

    try {

        const [meta] = await connection.query('SELECT * FROM Metas WHERE id_meta = ? AND id_usuario = ?', [id_meta, req.user.id_usuario]);

        if (meta.length === 0) {
            return res.status(404).json({ message: 'Meta não encontrada ou não pertence ao usuário' });
        }

        const deleteQuery = 'DELETE FROM Metas WHERE id_meta = ?'; 
        await connection.query(deleteQuery, [id_meta]);

        res.status(200).json({ message: 'Meta concluída e removida com sucesso' });
    } catch (error) {
        console.error('Erro ao excluir meta:', error);
        res.status(500).json({ message: 'Erro ao excluir meta' });
    }
});





app.post('/api/caracteristica', autenticarToken, async (req, res) => {
    const { Peso, Altura, imc } = req.body;

    if (!Peso || !Altura || !imc) {
        return res.status(400).json({ message: 'Por favor, insira uma caracteristica válida' });
    }

    try {
        const query = 'INSERT INTO Usuario_caract (id_usuario, Peso, Altura, imc) VALUES (?, ?, ?, ?)';
        await connection.query(query, [req.user.id_usuario, Peso, Altura, imc]);

        res.status(201).json({ message: 'Caracteristica registrada com sucesso' });
    } catch (error) {
        console.error('Erro ao registrar caracteristica:', error);
        res.status(500).json({ message: 'Erro ao registrar caracteristica' });
    }
});

app.post('/api/atividades', autenticarToken, async (req, res) => {
    const { atividade, data_treino } = req.body;

    if (!atividade || !data_treino) {
        return res.status(400).json({ message: 'Por favor, insira uma atividade válida' });
    }

    try {
        const query = 'INSERT INTO Atividades (id_usuario, atividade, data_treino) VALUES (?, ?, ?)';
        await connection.query(query, [req.user.id_usuario, atividade, data_treino]); 


        res.status(201).json({ message: 'Atividade registrada com sucesso' });
    } catch (error) {
        console.error('Erro ao registrar atividade:', error);
        res.status(500).json({ message: 'Erro ao registrar atividade' });
    }
});

app.get('/api/atividades', autenticarToken, async (req, res) => {
    try {

        const idUsuario = req.user.id_usuario;

        const query = 'SELECT * FROM Atividades WHERE id_usuario = ?';
        const [atividades] = await connection.query(query, [idUsuario]);


        if (atividades.length === 0) {
            return res.status(200).json({ atividades: [] });
        }

        return res.status(200).json({ atividades });
    } catch (error) {
        console.error('Erro ao buscar atividades:', error);
        res.status(500).json({ message: 'Erro ao buscar atividades' });
    }
});

app.get('/api/atividades-mensais', autenticarToken, async (req, res) => {
    try {
        const idUsuario = req.user.id_usuario;


        const query = `
            SELECT atividade, COUNT(*) as total
            FROM Atividades
            WHERE id_usuario = ? AND MONTH(data_treino) = MONTH(CURRENT_DATE()) AND YEAR(data_treino) = YEAR(CURRENT_DATE())
            GROUP BY atividade
        `;
        const [resultados] = await connection.query(query, [idUsuario]);

        res.status(200).json({ atividadesMensais: resultados });
    } catch (error) {
        console.error('Erro ao buscar contagem mensal:', error);
        res.status(500).json({ message: 'Erro ao buscar contagem mensal' });
    }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});