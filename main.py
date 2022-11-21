from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)
cors = CORS(app)

app.config["JWT_SECRET_KEY"] = "1Ds$9t7'YeyN|2,"
jwt = JWTManager(app)


@app.route("/login", methods=['POST'])
def login():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-security'] + "/usuarios/validate"
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(days=1)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"mensaje": "contraseña incorrecta"})


@app.route("/", methods=['GET'])
def test():
    json= {}
    json['message'] = "servidor corriendo MSQ"
    return json

#######################################
@app.route("/partidos", methods=['GET'])
def getPartidos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/partidos"
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partidos", methods=['POST'])
def createPartidos():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/partidos"
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>", methods=['PUT'])
def updatePartidos(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/partidos/" + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>", methods=['DELETE'])
def deletePartidos(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/partidos/" + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>", methods=['GET'])
def showPartidos(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/partidos/" + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

##################candidatos #####################
#######################################
@app.route("/candidatos", methods=['GET'])
def getCandidatos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/candidatos"
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos", methods=['POST'])
def createCandidatos():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/candidatos"
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>", methods=['PUT'])
def updateCandidatos(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/candidatos/" + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>", methods=['DELETE'])
def deleteCandidatos(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/candidatos/" + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>", methods=['GET'])
def showCandidatos(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/candidatos/" + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

##############      MESAS       ###################
@app.route("/mesas", methods=['GET'])
def getMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/mesas"
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesas", methods=['POST'])
def createMesas():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/mesas"
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/mesas/<string:id>", methods=['PUT'])
def updateMesas(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/mesas/" + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/mesas/<string:id>", methods=['DELETE'])
def deleteMesas(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/mesas/" + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesas/<string:id>", methods=['GET'])
def showMesas(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/mesas/" + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

#############  resultados  ###################
@app.route("/resultados", methods=['GET'])
def getResultados():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/resultados"
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados", methods=['POST'])
def createResultados():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/resultados"
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/<string:id>", methods=['PUT'])
def updateResultados(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/resultados/" + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/<string:id>", methods=['DELETE'])
def deleteResultados(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/resultados/" + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/<string:id>", methods=['GET'])
def showResultados(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-registry'] + "/resultados/" + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

#############ROLES####################
@app.route("/roles", methods=['GET'])
def getRoles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-security'] + "/roles"
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/roles", methods=['POST'])
def createRoles():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-security'] + "/roles"
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/roles/<string:id>", methods=['PUT'])
def updateRoles(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-security'] + "/roles/" + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/roles/<string:id>", methods=['DELETE'])
def deleteRoles(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-security'] + "/roles/" + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/roles/<string:id>", methods=['GET'])
def showRoles(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig['url-backend-security'] + "/roles/" + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.before_request
def before_request():
    endPoint = limpiarUrl(request.path)
    excludedRoutes  = ["/login", "/register", "/change-password"]
    if (excludedRoutes.__contains__(request.path)):
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"] is not None:
            tienePermiso = validarPermiso(endPoint, request.method, usuario["rol"]["_id"])
            if tienePermiso:
                pass
            else:
                return jsonify({"messgae": "Permiso denegado - Su Rol no esta autorizado para esta acción"})
        else:
            return jsonify({"message": "Permiso denegado, no se ha asignado el rol"})

def validarPermiso(endPoint, metodo, rol):
    url = dataConfig['url-backend-security'] + "/permisos-roles/validar-permiso/rol/" + str(rol)
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body = {
        "url": endPoint,
        "metodo": metodo
    }
    tienePermiso = False
    response = requests.get(url, json=body, headers=headers)
    try:
        data = response.json()
        if ("_id" in data):
            tienePermiso = True
    except:
        pass
    return tienePermiso

def limpiarUrl(url):
    partes = url.split("/")
    for parte in partes:
        if re.search('\\d', parte):
            url = url.replace(parte, "?")
    return url


def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data

if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Servidor ejecutandose... http://" + dataConfig['url-backend'] + ":" + str(dataConfig['port']))
    serve(app, host=dataConfig['url-backend'], port=dataConfig['port'])



