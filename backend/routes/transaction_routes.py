from flask import Blueprint, request, jsonify, Response
from models import db, User, Transaction
from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_DOWN
from markupsafe import escape
from auth import token_required, cookie_auth

transaction_bp = Blueprint('transaction', __name__)


def _parse_amount(raw):
    """Valida un monto: decimal con 2 decimales y estrictamente mayor que 0.

    Devuelve (Decimal, None) o (None, mensaje_error).
    """
    try:
        amount = Decimal(str(raw))
    except (InvalidOperation, ValueError, TypeError):
        return None, 'Monto invalido'
    if amount <= 0:
        return None, 'El monto debe ser mayor que cero'
    if amount != amount.quantize(Decimal('0.01'), rounding=ROUND_DOWN):
        return None, 'El monto admite como maximo 2 decimales'
    return amount, None


@transaction_bp.route('/api/transfer', methods=['POST'])
@token_required
def transfer(current_user):
    data = request.get_json(silent=True) or {}
    to_user_id = data.get('to_user_id')
    description = (data.get('description') or '')[:200]

    amount, err = _parse_amount(data.get('amount', 0))
    if err:
        return jsonify({'error': err}), 400

    receiver = User.query.get(to_user_id)
    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404
    if receiver.id == current_user.id:
        return jsonify({'error': 'No puede transferirse a si mismo'}), 400

    # Se valida el saldo ANTES de mover dinero; debito y credito en una sola
    # transaccion atomica. (OWASP A04 Insecure Design / logica de negocio)
    if current_user.balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400

    current_user.balance -= amount
    receiver.balance += amount
    transaction = Transaction(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        amount=amount,
        description=description,
        status='completed',
        completed_at=datetime.utcnow(),
    )
    db.session.add(transaction)
    db.session.commit()

    return jsonify({'message': 'Transfer successful', 'transaction': transaction.to_dict()})


@transaction_bp.route('/api/transactions', methods=['GET'])
@token_required
def get_transactions(current_user):
    # El usuario SIEMPRE es el de la sesion (se ignora user_id del query:
    # eliminaba IDOR y la inyeccion SQL del f-string). Consulta por el ORM.
    transactions = (
        Transaction.query
        .filter(
            (Transaction.sender_id == current_user.id)
            | (Transaction.receiver_id == current_user.id)
        )
        .order_by(Transaction.created_at.desc())
        .all()
    )
    return jsonify([t.to_dict() for t in transactions])


@transaction_bp.route('/api/transactions/<int:transaction_id>', methods=['GET'])
@token_required
def get_transaction(current_user, transaction_id):
    transaction = Transaction.query.get(transaction_id)

    if not transaction:
        return jsonify({'error': 'Transaction not found'}), 404

    if transaction.sender_id != current_user.id and transaction.receiver_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    return jsonify(transaction.to_dict())


@transaction_bp.route('/api/transactions/search', methods=['GET'])
@token_required
def search_transactions(current_user):
    search_term = (request.args.get('description', '') or '')[:100]

    # Consulta parametrizada del ORM con LIKE: elimina la inyeccion SQL y
    # mantiene el alcance al usuario actual. El '%' del termino se escapa.
    like = f"%{search_term}%"
    transactions = (
        Transaction.query
        .filter(
            (Transaction.sender_id == current_user.id)
            | (Transaction.receiver_id == current_user.id)
        )
        .filter(Transaction.description.ilike(like))
        .order_by(Transaction.created_at.desc())
        .all()
    )
    return jsonify([t.to_dict() for t in transactions])


@transaction_bp.route('/api/quickpay', methods=['POST'])
@cookie_auth
def quickpay(current_user):
    # CSRF mitigado por la cookie de sesion SameSite=Strict (ver auth_routes).
    body = request.get_json(silent=True) or {}
    to_user_id = request.form.get('to_user_id', body.get('to_user_id'))
    description = (request.form.get('description', body.get('description', 'QuickPay')) or '')[:200]

    amount, err = _parse_amount(request.form.get('amount', body.get('amount', 0)))
    if err:
        return jsonify({'error': err}), 400

    receiver = User.query.get(to_user_id)
    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404
    if receiver.id == current_user.id:
        return jsonify({'error': 'No puede transferirse a si mismo'}), 400

    if current_user.balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400

    current_user.balance -= amount
    receiver.balance += amount
    transaction = Transaction(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        amount=amount,
        description=description,
        status='completed',
        completed_at=datetime.utcnow(),
    )
    db.session.add(transaction)
    db.session.commit()

    return jsonify({'message': 'QuickPay sent', 'transaction': transaction.to_dict()})


@transaction_bp.route('/api/transactions/<int:transaction_id>/receipt', methods=['GET'])
@token_required
def transaction_receipt(current_user, transaction_id):
    transaction = Transaction.query.get(transaction_id)
    if not transaction:
        return jsonify({'error': 'Receipt not found'}), 404

    # Autenticacion + autorizacion: solo una parte de la transaccion ve el recibo.
    if transaction.sender_id != current_user.id and transaction.receiver_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    sender = User.query.get(transaction.sender_id)
    receiver = User.query.get(transaction.receiver_id)
    sender_name = sender.username if sender else 'unknown'
    receiver_name = receiver.username if receiver else 'unknown'

    # Todo dato dinamico se escapa con markupsafe antes de ir al HTML (anti XSS).
    html = f"""<!doctype html>
<html>
  <head><title>DVBank Receipt #{escape(transaction.id)}</title></head>
  <body style="font-family: sans-serif; max-width: 600px; margin: 40px auto;">
    <h1>DVBank Payment Receipt</h1>
    <p><b>Receipt #:</b> {escape(transaction.id)}</p>
    <p><b>From:</b> {escape(sender_name)}</p>
    <p><b>To:</b> {escape(receiver_name)}</p>
    <p><b>Amount:</b> ${float(transaction.amount):.2f}</p>
    <p><b>Status:</b> {escape(transaction.status)}</p>
    <p><b>Memo:</b> {escape(transaction.description or '')}</p>
    <hr/>
    <small>Generated {escape(datetime.utcnow().isoformat())}</small>
  </body>
</html>"""
    resp = Response(html, content_type='text/html; charset=utf-8')
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'"
    return resp


@transaction_bp.route('/api/split-bill', methods=['POST'])
@token_required
def split_bill(current_user):
    data = request.get_json(silent=True) or {}
    to_user_id = data.get('to_user_id')
    description = (data.get('description') or 'Bill split')[:200]

    amount, err = _parse_amount(data.get('amount', 0))
    if err:
        return jsonify({'error': err}), 400

    # El que paga es SIEMPRE el usuario de la sesion (antes se tomaba
    # from_user_id del cliente: permitia debitar cuentas ajenas). OWASP A01.
    payer = current_user
    payee = User.query.get(to_user_id)
    if not payee:
        return jsonify({'error': 'User not found'}), 404
    if payee.id == payer.id:
        return jsonify({'error': 'Destinatario invalido'}), 400

    if payer.balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400

    payer.balance -= amount
    payee.balance += amount
    transaction = Transaction(
        sender_id=payer.id,
        receiver_id=payee.id,
        amount=amount,
        description=description,
        status='completed',
        completed_at=datetime.utcnow(),
    )
    db.session.add(transaction)
    db.session.commit()

    return jsonify({'message': 'Bill split', 'transaction': transaction.to_dict()})
