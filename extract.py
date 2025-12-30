import sqlite3
import os
def export_sqlite_to_txt(db_path):
    # Automatically generate txt file name
    base_name = os.path.splitext(db_path)[0]
    txt_path = base_name + ".txt"
    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    with open(txt_path, 'a', encoding='utf-8') as f:
        # Get all table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        if not tables:
            f.write("No tables found in the database.\n")
            print("No tables found in the database.")
            return
        for (table_name,) in tables:
            f.write(f"==== Table: {table_name} ====\n")
            print(f"Exporting table: {table_name}")
            # Get table structure
            cursor.execute(f'PRAGMA table_info("{table_name}")')
            columns = cursor.fetchall()
            col_names = [col[1] for col in columns]
            col_names_line = "\t".join(col_names)
            f.write(f"Columns: {col_names_line}\n")
            # Get all data in the table
            cursor.execute(f'SELECT * FROM "{table_name}"')
            rows = cursor.fetchall()
            for row in rows:
                line = "\t".join([str(col) for col in row])
                f.write(f"{line}\n")
            f.write("\n")
    cursor.close()
    conn.close()
    print(f"Export complete, all content has been appended to {txt_path}")
if __name__ == '__main__':
    db_path = input('Please enter the path to the SQLite database (e.g., test.db): ').strip()
    export_sqlite_to_txt(db_path)
