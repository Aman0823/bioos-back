import json
import os
import re
from datetime import timedelta
from functools import wraps
import bcrypt
from flask import Flask, request, jsonify
from volcengine.bioos.BioOsService import BioOsService
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)

#登录令牌
app.config['JWT_SECRET_KEY'] = os.urandom(24)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=60*24*30)  # 设置访问令牌的有效期为一个月
# 允许所有源的跨域请求
CORS(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80),nullable=False)
    user_id = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), unique=False, nullable=False)
    user_ak = db.Column(db.String(500), unique=True, nullable=True)
    user_sk = db.Column(db.String(500), unique=True, nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password = hash_password(password)

    def check_password(self, password):
        return check_password(self.password, password)


def set_ak_sk_global(id):
    user = User.query.get(id)
    global ak
    ak = user.user_ak
    bioos_service.set_ak(ak)
    global sk
    sk = user.user_sk
    bioos_service.set_sk(sk)

# 自定义装饰器，用于处理JWT验证和错误响应
def jwt_auth_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        if not current_user_id:
            return jsonify({"error": "User not authenticated"}), 401
        return f(*args, **kwargs)
    return decorated_function

# 生成盐并哈希密码的函数
def hash_password(password):
    # 生成盐
    salt = bcrypt.gensalt()
    # 使用盐哈希密码
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

# 验证密码是否匹配哈希值的函数
def check_password(hashed, password):
    # 验证密码是否与哈希值匹配
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def find_user_by_id(user_id):
    user = User.query.get(user_id)
    return user

bioos_service = BioOsService(endpoint='https://open.volcengineapi.com', region='cn-beijing')


#   get user ak and sk
@app.route('/users', methods=['GET'])
@jwt_auth_required
def get_users():
    users = User.query.all()
    return jsonify(
        [{'id': user.id, 'user_id':user.user_id, 'username': user.username, 'user_ak': user.user_ak, 'user_sk': user.user_sk} for user in
         users])

#登录
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user_id = data.get('user_id')
    password = data.get('password')
    print(data)
    # 检查是否提供了必要的凭证
    if not user_id or not password:
        return jsonify({"msg": "Missing credentials"}), 401

        # 从数据库中获取用户
    user = User.query.filter_by(user_id=user_id).first()

    # 检查用户是否存在
    if user is None:
        return jsonify({"msg": "User not found"}), 404

        # 检查密码是否正确
    if check_password(user.password, password):
        access_token = create_access_token(identity={'user_id': user.id})  # 注意使用 user.id 而不是 user_id（取决于您的模型定义）
        return jsonify(
            access_token=access_token,
            success=1,
            username=user.username,
            id=user.id,
            user_ak=user.user_ak,
            user_sk=user.user_sk
        ), 200
    else:
        return jsonify({"msg": "Bad credentials"}), 401

    # 获取用户信息
@app.route('/get_user', methods=['GET'])
@jwt_auth_required
def get_user():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400
    user = User.query.filter_by(user_id=user_id).first()
    if user is None:
        return jsonify({"error": "User not found"}), 404  # 返回用户信息，排除密码等敏感信息
    user_data = {
        "id": user.id,
        "username": user.username,
        "user_id": user.user_id,
        "user_ak": user.user_ak,
        "user_sk": user.user_sk
    }
    return jsonify(user_data)


# 修改密码
@app.route('/change_password', methods=['POST'])
@jwt_auth_required
def change_password():
    data = request.get_json()
    user_id = data.get('user_id')
    password = data.get('password')
    new_password = data.get('new_password')
    user = User.query.filter_by(user_id=user_id).first()

    if not user_id or not new_password:
        return jsonify({"error": "user_id and new_password are required"}), 400

    if user is None:
        return jsonify({"error": "User not found"}), 404

    if not check_password(user.password, password):
        return jsonify({"error": "Passwords do not match"}), 400

    user.password = hash_password(new_password)
    db.session.commit()
    return jsonify({"message": "修改密码成功！"}), 200


# 每次调用接口时先调用这个函数，设置全局参数
@app.route('/set-ak-sk/<int:id>', methods=['GET'])
def set_ak_sk(id):
    print(f"Request received for ID: {id}")  # 打印请求的 ID
    set_ak_sk_global(id)  # 调用函数设置全局变量
    return jsonify({'ak': ak, 'sk': sk})


# 创建用户
#   create user
@app.route('/create_user', methods=['POST'])
def create_user():
    data = request.get_json()

    # 验证user_id是否为10位
    if 'user_id' not in data or not re.match(r'^\d{10}$', data['user_id']):
        return jsonify({'message': 'Invalid user_id. It must be a 10-digit number.'}), 400

        # 验证密码长度是否在6到16位之间
    if 'password' not in data or not (6 <= len(data['password']) <= 16):
        return jsonify({'message': 'Invalid password. It must be between 6 and 16 characters long.'}), 400

        # 验证username和user_id是否已存在
    existing_user_by_id = User.query.filter_by(user_id=data['user_id']).first()
    existing_user_by_name = User.query.filter_by(username=data['username']).first()

    if existing_user_by_id:
        return jsonify({'message': 'User with this user_id already exists.'}), 400
    if existing_user_by_name:
        return jsonify({'message': 'User with this username already exists.'}), 400
        # 如果验证通过，则创建新用户
    new_user = User(
        username=data['username'],
        password=hash_password(data['password']),
        user_id=data['user_id']
    )

    # 将新用户添加到数据库会话中并提交
    db.session.add(new_user)
    db.session.commit()

    # 返回成功响应
    return jsonify({'message': 'User created!'}), 200


# 创建工作空间
@app.route('/create_workspace', methods=['POST'])
@jwt_auth_required
def create_workspace():
    params = request.json
    try:
        resp = bioos_service.create_workspace(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# 更新工作空间
@app.route('/update_workspace', methods=['POST'])
@jwt_auth_required
def update_workspace():
    data = request.get_json()
    params = {
        'ID': data.get('ID'),
        'Name': data.get('Name'),
        'Description': data.get('Description'),
        'CoverPath': data.get('CoverPath')
    }
    try:
        resp = bioos_service.update_workspace(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 删除工作空间
@app.route('/delete_workspace', methods=['POST'])
@jwt_auth_required
def delete_workspace():
    data = request.get_json()
    params = {
        'ID': data.get('ID')  # 从请求数据中获取工作区 ID
    }
    try:
        resp = bioos_service.delete_workspace(params)
        return jsonify(resp + "success!"), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 获取工作空间列表
#  get workspaces list
@app.route('/list_workspaces', methods=['GET'])
@jwt_auth_required
def list_workspaces():
    params = {}
    try:
        resp = bioos_service.list_workspaces(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# 绑定集群
@app.route('/bind_cluster_to_workspace', methods=['POST'])
@jwt_auth_required
def bind_cluster_to_workspace():
    data = request.get_json()
    params = {
        'ID': data.get('ID'),  # 从请求数据中获取工作区 ID ,
        'ClusterID': data.get('ClusterID'),  # 从请求数据中获取集群 ID
        'Type': data.get('Type')  # 从请求数据中获取类型
    }
    try:
        resp = bioos_service.bind_cluster_to_workspace(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 解绑集群
@app.route('/unbind_cluster_and_workspace', methods=['POST'])
@jwt_auth_required
def unbind_cluster_and_workspace():
    data = request.get_json()
    params = {
        'ID': data.get('ID'),  # 从请求数据中获取工作区 ID
        'ClusterID': data.get('ClusterID'),  # 从请求数据中获取集群 ID
        'Type': data.get('Type')  # 从请求数据中获取类型
    }
    try:
        resp = bioos_service.unbind_cluster_and_workspace(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# 获取工作空间的标签列表
@app.route('/list_workspace_labels', methods=['POST'])
@jwt_auth_required
def list_workspace_labels():
    # 创建参数字典
    params = {}
    try:
        resp = bioos_service.list_workspace_labels(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 创建集群


# 集群列表
@app.route('/list_clusters', methods=['POST'])
@jwt_auth_required
def list_clusters():
    data = request.get_json()
    params = {
        'PageNumber': data.get('PageNumber', 1),  # 从请求数据中获取页码，默认为1
        'PageSize': data.get('PageSize', 10),  # 从请求数据中获取每页数量，默认为10
        'Filter': {
            'IDs': data.get('Filter', {}).get('IDs', []),  # 获取 IDs 列表
            'Status': data.get('Filter', {}).get('Status', []),  # 获取状态列表
            'Type': data.get('Filter', {}).get('Type', []),  # 获取类型列表
            'Public': data.get('Filter', {}).get('Public', False),  # 获取公有属性，默认为 False
        },
    }

    try:
        resp = bioos_service.list_clusters(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 删除集群
@app.route('/delete_cluster', methods=['POST'])
@jwt_auth_required
def delete_cluster():
    data = request.get_json()

    # 从请求中提取必要参数，例如
    params = {
        'ClusterID': data.get('ClusterID')  # 确保传递 ClusterID 参数
    }
    try:
        resp = bioos_service.delete_cluster(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 创建工作流
@app.route('/create_workflow', methods=['POST'])
@jwt_auth_required
def create_workflow():
    data = request.get_json()

    # 从请求中提取参数
    params = {
        'WorkspaceID': data.get('WorkspaceID'),
        'Name': data.get('Name'),
        'Description': data.get('Description'),
        'Language': data.get('Language', 'WDL'),  # 默认值为 WDL
        'Source': data.get('Source'),
        'Tag': data.get('Tag'),
        'MainWorkflowPath': data.get('MainWorkflowPath'),
    }
    try:
        resp = bioos_service.create_workflow(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 获取工作流列表
@app.route('/list_workflows', methods=['POST'])
@jwt_auth_required
def list_workflows():
    data = request.get_json()

    # 从请求中提取参数
    params = {
        'WorkspaceID': data.get('WorkspaceID'),
        'SortBy': data.get('SortBy', 'CreateTime'),  # 默认排序方式为 CreateTime
        'PageNumber': data.get('PageNumber', 1),  # 默认页码为1
        'PageSize': data.get('PageSize', 10),  # 默认每页大小为10
        'SortOrder': data.get('SortOrder', 'DESC'),  # 默认排序顺序为 DESC
    }

    try:
        resp = bioos_service.list_workflows(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 更新工作流
@app.route('/update_workflow', methods=['POST'])
@jwt_auth_required
def update_workflow():
    data = request.get_json()

    # 从请求中提取参数
    params = {
        'WorkspaceID': data.get('WorkspaceID'),
        'ID': data.get('ID'),
        'Name': data.get('Name'),
        'Description': data.get('Description'),
        'Source': data.get('Source'),
        'Tag': data.get('Tag'),
        'Token': data.get('Token'),
        'MainWorkflowPath': data.get('MainWorkflowPath'),
    }

    try:
        resp = bioos_service.update_workflow(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 删除工作流
@app.route('/delete_workflow', methods=['DELETE'])
@jwt_auth_required
def delete_workflow():
    # 从请求中获取参数
    data = request.get_json()

    params = {
        'WorkspaceID': data.get('WorkspaceID'),
        'ID': data.get('ID')
    }

    try:
        resp = bioos_service.delete_workflow(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 查询TRS协议工作流信息
@app.route('/get_trs_workflow_info', methods=['POST'])
@jwt_auth_required
def get_trs_workflow_info():
    # 从请求中获取参数
    data = request.get_json()

    params = {
        "TRSServer": data.get("TRSServer"),
        "ID": data.get("ID")
    }

    try:
        resp = bioos_service.get_trs_workflow_info(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 获取notebook列表
@app.route('/list_notebook_servers', methods=['GET'])
@jwt_auth_required
def list_notebook_servers():

    #从请求中获取分页信息和筛选条件
    page_number = request.args.get('PageNumber', default=1, type=int)
    page_size = request.args.get('PageSize', default=10, type=int)
    workspace_id = request.args.get('WorkspaceID')
    user_id = request.args.get('UserID', type=int) #解析为整数
    status = request.args.get('Status', default='["spawn"]')
    sort_by = request.args.get('SortBy', default='OwnerName')
    sort_order = request.args.get('SortOrder', default='Desc')

    if not workspace_id:
        return jsonify({"error": "WorkspaceID is required."}),400
    try:

        #构建参数
        params = {
        "PageNumber": page_number,
        "PageSize": page_size,
        "Filter": {
            "Status": status,
            "WorkspaceID": workspace_id,
            "UserID": user_id
        },
        "SortBy": sort_by,
        "SortOrder": sort_order
        }

        resp = bioos_service.list_notebook_servers(params)
        return jsonify(resp),200
    except Exception as e:
        return jsonify({"error": str(e)}),500


# 获取数据列表
@app.route('/api/list_data_files', methods=['GET'])
def list_data_files():
    # 从请求中获取参数
    dataset_id = request.args.get('DataSetID')
    page_number = request.args.get('PageNumber', default=1, type=int)
    page_size = request.args.get('PageSize', default=10, type=int)
    ids = request.args.getlist('IDs') # 可以传递多个数据文件 ID
    file_type = request.args.getlist('FileType') # 可以传递多个文件类型
    keyword = request.args.get('Keyword', default='')

    if not dataset_id:
        return jsonify({"error": "DataSetID is required."}),400 # 构建参数
    params = {
    "DataSetID": dataset_id,
    "PageNumber": page_number,
    "PageSize": page_size,
    "Filter": {
        "IDs": ids,
        "FileType": file_type,
        "Keyword": keyword
    },
    "SortBy": "Name",
    "SortOrder": "Desc"
    }

    try:
        # 调用获取数据文件列表的方法
        resp = bioos_service.list_data_files(params)
        return jsonify(resp),200
    except Exception as e:
        return jsonify({"error": str(e)}),500

# 创建数据模型
@app.route('/create_data_model', methods=['POST'])
@jwt_auth_required
def create_data_model():
    # 从请求中获取参数
    data = request.get_json()

    params = {
        'WorkspaceID': data.get('WorkspaceID'),
        'Name': data.get('Name'),
        'Headers': data.get('Headers'),
        'Rows': data.get('Rows')
    }

    try:
        resp = bioos_service.create_data_model(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 查询数据模型列表
@app.route('/list_data_models', methods=['POST'])
@jwt_auth_required
def list_data_models():
    # 从请求中获取参数
    data = request.get_json()

    params = {
        'WorkspaceID': data.get('WorkspaceID'),
    }

    try:
        resp = bioos_service.list_data_models(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 删除数据模型行或列
@app.route('/delete_data_model_rows_and_headers', methods=['POST'])
@jwt_auth_required
def delete_data_model_rows_and_headers():
    # 从请求中获取参数
    data = request.get_json()

    params = {
        'WorkspaceID': data.get('WorkspaceID'),
        'ID': data.get('ID'),
        'RowIDs': data.get('RowIDs'),
    }

    try:
        resp = bioos_service.delete_data_model_rows_and_headers(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 获取数据模型所有行ID


# 终止投递记录
@app.route('/cancel_submission', methods=['POST'])
@jwt_auth_required
def cancel_submission():
    # 从请求中获取参数
    data = request.get_json()

    params = {
        'WorkspaceID': data.get('WorkspaceID'),
        'ID': data.get('ID'),
    }

    try:
        resp = bioos_service.cancel_submission(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 投递工作流
@app.route('/create_submission', methods=['POST'])
@jwt_auth_required
def create_submission():
    # 从请求中获取参数
    data = request.get_json()
    # 构建参数
    params = {
        'ClusterID': data.get('ClusterID'),
        'WorkspaceID': data.get('WorkspaceID'),
        'WorkflowID': data.get('WorkflowID'),
        'Name': data.get('Name'),
        'Description': data.get('Description'),
        'DataModelID': data.get('DataModelID'),
        'DataModelRowIDs': data.get('DataModelRowIDs'),
        'Inputs': json.dumps(data.get('Inputs')),
        'ExposedOptions': data.get('ExposedOptions', {}),
        'Outputs': json.dumps(data.get('Outputs')),
    }

    try:
        resp = bioos_service.create_submission(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 获取投递记录列表
@app.route('/get_submissions', methods=['GET'])
@jwt_auth_required
def get_submissions():
    # 从请求中获取工作区 ID
    workspace_id = request.args.get('WorkspaceID')

    if not workspace_id:
        return jsonify({"error": "WorkspaceID is required."}), 400
    try:
        # 调用获取提交记录的方法（假设有个特别的API方法）
        params = {
            'WorkspaceID': workspace_id,
        }
        resp = bioos_service.list_submissions(params)  # 假设有这个方法
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 获取运行记录列表
@app.route('/list_runs', methods=['GET'])
@jwt_auth_required
def list_runs():
    # 从请求中获取工作区 ID 和筛选条件
    workspace_id = request.args.get('WorkspaceID')
    run_ids = request.args.getlist('IDs')  # 可以传多个 run_id
    if not workspace_id:
        return jsonify({"error": "WorkspaceID is required."}), 400
    try:
        # 构建参数
        params = {
            'WorkspaceID': workspace_id,
            'Filter': {'IDs': run_ids},
        }
        # 调用获取运行记录列表的方法
        resp = bioos_service.list_runs(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

#终止运行记录
@app.route('/cancel_run', methods=['POST'])
@jwt_auth_required
def cancel_run():
    # 从请求中获取工作区 ID 和运行 ID
    workspace_id = request.json.get('WorkspaceID')
    run_id = request.json.get('ID')

    if not workspace_id or not run_id:
        return jsonify({"error": "WorkspaceID and ID are required."}), 400
    try:
        # 构建参数
        params = {
            'WorkspaceID': workspace_id,
            'ID': run_id,
        }
        # 调用取消运行的方法
        resp = bioos_service.cancel_run(params)
        return jsonify(resp), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


#     run app
if __name__ == '__main__':
    db.create_all()  # 创建数据库
    app.run(port=5000)  # 运行Flask应用
