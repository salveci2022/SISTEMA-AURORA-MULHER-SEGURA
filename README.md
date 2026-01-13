# Aurora Mulher Segura — V21

## Rodar local
pip install -r requirements.txt
python app.py

## Render Start Command
gunicorn app:app

## Links
/panic (mulher)
/panel/login (admin: admin / admin123)
/trusted/login (pessoa de confiança)
/health (diagnóstico)

## Mudanças V21
- Horário Brasil (America/Sao_Paulo) nos alertas
- Painel da mulher mostra as pessoas de confiança cadastradas
- Localização só é solicitada se a usuária marcar "Compartilhar localização"
- Logout da pessoa de confiança volta para o login dela (precisa logar novamente)


## Correção V22
- Corrige erro de fuso no Windows (tzdata). Se necessário, instale com: `pip install tzdata`.
