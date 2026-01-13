#!/usr/bin/env python3
"""
SCRIPT PARA MIGRAR ARQUIVOS JSON PARA FORMATO SEGURO
Execute: python migrate_json.py
"""

import json
import hashlib
import secrets
from datetime import datetime
from pathlib import Path

def hash_password(password: str) -> str:
    """Gera hash seguro para senha."""
    salt = secrets.token_hex(16)
    return salt + ":" + hashlib.sha256((salt + password).encode()).hexdigest()

def now_str() -> str:
    """Retorna timestamp atual formatado."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def migrate_users_json():
    """Migra users.json para formato seguro."""
    users_file = Path("users.json")
    
    if not users_file.exists():
        print("❌ ERRO: users.json não encontrado!")
        return False
    
    try:
        # Carrega dados atuais
        with open(users_file, "r", encoding="utf-8") as f:
            users = json.load(f)
        
        print(f"📊 Carregados {len(users)} usuários...")
        
        migrated = False
        for username, info in users.items():
            # 1. Converter senhas para hash (se ainda não estiverem)
            current_password = info.get("password", "")
            if current_password and ":" not in current_password:
                print(f"  🔐 Convertendo senha de '{username}' para hash...")
                info["password"] = hash_password(current_password)
                migrated = True
            
            # 2. Adicionar campos obrigatórios
            if "created_at" not in info:
                info["created_at"] = now_str()
                migrated = True
            
            # 3. Campos específicos por role
            if info.get("role") == "admin" and "must_change_password" not in info:
                info["must_change_password"] = True
                migrated = True
            
            if info.get("role") == "trusted" and "password_changed_at" not in info:
                info["password_changed_at"] = now_str()
                migrated = True
            
            if "last_login" not in info:
                info["last_login"] = None
                migrated = True
        
        if migrated:
            # Salva backup do arquivo original
            backup_file = users_file.with_suffix(".json.backup")
            import shutil
            shutil.copy2(users_file, backup_file)
            print(f"  💾 Backup salvo em: {backup_file}")
            
            # Salva novo arquivo
            with open(users_file, "w", encoding="utf-8") as f:
                json.dump(users, f, indent=2, ensure_ascii=False)
            
            print("✅ users.json migrado com sucesso!")
            print("\n📋 RESUMO DOS USUÁRIOS:")
            for username, info in users.items():
                role = info.get("role", "unknown")
                name = info.get("name", username)
                has_hash = ":" in info.get("password", "")
                print(f"  👤 {name} ({username}): {role} - {'🔒 Hash OK' if has_hash else '❌ Senha em texto'}")
        else:
            print("✅ users.json já está no formato correto!")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro ao migrar users.json: {e}")
        return False

def migrate_state_json():
    """Migra state.json para formato seguro."""
    state_file = Path("state.json")
    
    if not state_file.exists():
        print("❌ ERRO: state.json não encontrado!")
        return False
    
    try:
        # Carrega dados atuais
        with open(state_file, "r", encoding="utf-8") as f:
            state = json.load(f)
        
        migrated = False
        
        # Adicionar campos obrigatórios
        if "created_at" not in state:
            state["created_at"] = now_str()
            migrated = True
        
        if "updated_at" not in state:
            state["updated_at"] = now_str()
            migrated = True
        
        if migrated:
            # Salva backup
            backup_file = state_file.with_suffix(".json.backup")
            import shutil
            shutil.copy2(state_file, backup_file)
            print(f"  💾 Backup salvo em: {backup_file}")
            
            # Salva novo arquivo
            with open(state_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, ensure_ascii=False)
            
            print(f"✅ state.json migrado! Último ID: {state.get('last_id', 0)}")
        else:
            print("✅ state.json já está no formato correto!")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro ao migrar state.json: {e}")
        return False

def create_missing_files():
    """Cria arquivos que podem estar faltando."""
    base_files = [
        "failed_logins.json",
        "alerts.log",
        "app.log"
    ]
    
    for file_name in base_files:
        file_path = Path(file_name)
        if not file_path.exists():
            try:
                if file_name.endswith(".json"):
                    with open(file_path, "w", encoding="utf-8") as f:
                        json.dump({}, f, indent=2)
                else:
                    file_path.touch()
                print(f"📄 Criado: {file_name}")
            except Exception as e:
                print(f"⚠️  Não foi possível criar {file_name}: {e}")

if __name__ == "__main__":
    print("=" * 50)
    print("🚀 MIGRAÇÃO DE ARQUIVOS JSON - AURORA MULHER SEGURA")
    print("=" * 50)
    
    success = True
    
    # 1. Criar arquivos faltantes
    print("\n📁 VERIFICANDO ARQUIVOS NECESSÁRIOS...")
    create_missing_files()
    
    # 2. Migrar users.json
    print("\n👥 MIGRANDO users.json...")
    if not migrate_users_json():
        success = False
    
    # 3. Migrar state.json
    print("\n🆔 MIGRANDO state.json...")
    if not migrate_state_json():
        success = False
    
    # 4. Resultado final
    print("\n" + "=" * 50)
    if success:
        print("🎉 MIGRAÇÃO CONCLUÍDA COM SUCESSO!")
        print("\n⚠️  IMPORTANTE:")
        print("   1. Altere a senha do admin ao fazer o primeiro login!")
        print("   2. Verifique se os backups foram criados")
        print("   3. Execute o sistema com: python app.py")
    else:
        print("❌ MIGRAÇÃO COM PROBLEMAS!")
        print("   Verifique os erros acima.")
    
    print("=" * 50)