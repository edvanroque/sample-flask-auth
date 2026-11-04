import os
import bcrypt
from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"

# Caminho absoluto para a base SQLite na pasta instance
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'instance', 'database.db')}"
app.json.ensure_ascii = False

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

# View para redirecionamento padrão do Flask-Login
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rota de Registro/Cadastro de Novo Usuário (com hash da senha)
@app.route('/user', methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        # Gera o salt e cria o hash da senha em bytes
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        
        # Cria o usuário salvando o hash (decodificado como string utf-8 no banco)
        user = User(username=username, password=hashed_password.decode('utf-8'))
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso!"}), 201

    return jsonify({"message": "Dados inválidos"}), 400

@app.route('/login', methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User.query.filter_by(username=username).first()

        # Valida senha: tanto se for hash bcrypt quanto senha antiga em texto puro
        if user:
            password_matches = False
            user_password_bytes = user.password.encode('utf-8')

            # Verifica se o banco já contém um hash bcrypt válido ($2b$...)
            if user_password_bytes.startswith(b'$2b$') or user_password_bytes.startswith(b'$2a$'):
                password_matches = bcrypt.checkpw(str.encode(password), user_password_bytes)
            else:
                password_matches = (user.password == password)

            if password_matches:
                login_user(user)
                print("Usuário autenticado:", current_user.is_authenticated)
                return jsonify({"message": "Autenticação realizada com sucesso!"})

    return jsonify({"message": "Credenciais inválidas"}), 400

@app.route('/logout', methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso!"})

@app.route('/user/<int:id_user>', methods=["GET"])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)

    if user:
        return jsonify({"username": user.username})

    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/user/<int:id_user>', methods=["PUT"])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)

    # Impede que um usuário altere a senha de terceiros
    if id_user != current_user.id:
        return jsonify({"message": "Operação não permitida"}), 403

    if user and data.get("password"):
        new_password = data.get("password")
        hashed_password = bcrypt.hashpw(str.encode(new_password), bcrypt.gensalt())
        user.password = hashed_password.decode('utf-8')
        db.session.commit()
        return jsonify({"message": f"Usuário {id_user} atualizado com sucesso!"})

    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/user/<int:id_user>', methods=["DELETE"])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)

    # Impede que um usuário comum delete terceiros
    if id_user != current_user.id:
        return jsonify({"message": "Operação não permitida"}), 403

    if user:
        if current_user.id == user.id:
            logout_user()

        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Usuário {id_user} deletado com sucesso!"})

    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route("/hello-world", methods=["GET"])
def hello_world():
    return "Hello world"

if __name__ == '__main__':
    app.run(debug=True)