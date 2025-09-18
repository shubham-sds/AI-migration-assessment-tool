import sqlite3
import pandas as pd
from itertools import zip_longest

def export_db_schema_pivoted(db_file, excel_file):
    """
    Connects to an SQLite database and creates a single Excel sheet where
    each database table is a column, listing its own column names vertically.

    Args:
        db_file (str): The path to the SQLite database file.
        excel_file (str): The name of the Excel file to create.
    """
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Get all table names from the database
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        # A dictionary to hold the schema: {table_name: [col1, col2, ...]}
        schema_dict = {}

        # Loop through each table to get its columns
        for table_name in tables:
            table_name = table_name[0]
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()
            # Store just the column names in the dictionary
            schema_dict[table_name] = [column[1] for column in columns]

        # Create a DataFrame from the dictionary.
        # Because the lists of column names can have different lengths,
        # pandas will automatically fill shorter columns with empty values (NaN).
        df = pd.DataFrame.from_dict(schema_dict, orient='index').transpose()


        # Write the DataFrame to a single Excel sheet
        df.to_excel(excel_file, index=False)

        print(f"Successfully created pivoted schema file: '{excel_file}'")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Ensure the database connection is closed
        if conn:
            conn.close()

# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
#                              HOW TO USE
# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
# 1. Make sure you have Python, pandas, and openpyxl installed.
# 2. Save this code as a Python file (e.g., `export_pivoted_schema.py`).
# 3. Place this file in the SAME FOLDER as your `assessment_history.db` file.
# 4. Run the script from your terminal: python export_pivoted_schema.py
# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---

if __name__ == '__main__':
    database_file = 'assessment_history.db'
    output_excel_file = 'database_schema_pivoted.xlsx'
    export_db_schema_pivoted(database_file, output_excel_file)