from flask import Blueprint, request, jsonify
from app import db
from app.models.sector import Sector
from app.models.user import User
from app.utils.decorators import require_auth, require_admin

sectors_bp = Blueprint('sectors', __name__)

@sectors_bp.route('/', methods=['GET'])
@require_auth
def list_sectors():
    sectors = Sector.query.filter_by(is_personal=False).order_by(Sector.name).all()
    return jsonify({'sectors': [s.to_dict() for s in sectors]}), 200

@sectors_bp.route('/<int:sector_id>', methods=['GET'])
@require_auth
def get_sector(sector_id):
    sector = Sector.query.get(sector_id)
    if not sector:
        return jsonify({'error': 'Setor não encontrado'}), 404
    return jsonify({'sector': sector.to_dict()}), 200

@sectors_bp.route('/', methods=['POST'])
@require_admin
def create_sector():
    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({'error': 'Nome do setor é obrigatório'}), 400

    name = data['name'].strip()
    if Sector.query.filter_by(name=name).first():
        return jsonify({'error': 'Setor já existe'}), 409

    sector = Sector(name=name, description=data.get('description'))
    db.session.add(sector)
    db.session.commit()

    return jsonify({'success': True, 'sector': sector.to_dict()}), 201

@sectors_bp.route('/<int:sector_id>', methods=['PUT'])
@require_admin
def update_sector(sector_id):
    sector = Sector.query.get(sector_id)
    if not sector:
        return jsonify({'error': 'Setor não encontrado'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Nenhum dado fornecido'}), 400

    if 'name' in data:
        name = data['name'].strip()
        existing = Sector.query.filter_by(name=name).first()
        if existing and existing.id != sector_id:
            return jsonify({'error': 'Nome de setor já existe'}), 409
        sector.name = name
    if 'description' in data:
        sector.description = data['description']

    db.session.commit()
    return jsonify({'success': True, 'sector': sector.to_dict()}), 200

@sectors_bp.route('/<int:sector_id>', methods=['DELETE'])
@require_admin
def delete_sector(sector_id):
    sector = Sector.query.get(sector_id)
    if not sector:
        return jsonify({'error': 'Setor não encontrado'}), 404

    name = sector.name
    db.session.delete(sector)
    db.session.commit()

    return jsonify({'success': True, 'message': f'Setor {name} excluído'}), 200
