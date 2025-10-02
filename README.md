** Database e dashboard di CVE per analisi vulnerabilità **

Questa versione monta `init_db.sql` dentro il container Postgres usando `/docker-entrypoint-initdb.d/`,
quindi il database viene inizializzato automaticamente al primo avvio senza comandi manuali.

Il progetto deve avere i file inseriti nella propria cartella in questo modo:
init_db.sql
docker-compose.yml
requirements.txt
api/
    main.py
    Dockerfile
    requirements.txt
worker/
    worker.py
    Dockerfile
    requirements.txt
    
Come avviarlo (dev):
1. Build and start with docker-compose:
   ```
   docker compose up --build
   ```
2. Se tu avevi giá avviato prima il database e vuoi riavviare di nuovo l'init, dovresti rimuovere il volume:
   ```
   docker compose down -v
   docker compose up --build
   ```
3. API sará disponibile qui http://localhost:8000
   - docs: http://localhost:8000/docs
  

Tecnologie usate:

Python
PostgreSQL
Docker
