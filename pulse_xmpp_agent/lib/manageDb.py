import sqlite3
import threading
import logging

logger = logging.getLogger()


class ManageDb:
    path = ""
    tablename = ""
    instances = {}

    def __new__(kls, *args, **kwargs):
        if kls not in ManageDb.instances:
            self = object.__new__(kls, *args, **kwargs)
            kls.instances[kls] = self
        return ManageDb.instances[kls]

    def __init__(self):
        self.local_storage = threading.local()  # Store a connection per thread
        self.path = self.path or "database_default.db"

    def get_connection(self):
        """
        Open a new SQLite connection for each thread if it does not yet exist.

        Returns
        -------
        sqlite3.Connection
            A SQLite connection for the current thread.
        """
        if not hasattr(self.local_storage, "connection"):
            try:
                self.local_storage.connection = sqlite3.connect(
                    self.path, check_same_thread=False
                )
                self.activate(self.local_storage.connection)
            except sqlite3.Error as e:
                logger.error(f"Error while opening the SQLite database: {e}")
        return self.local_storage.connection

    def close(self):
        """
        Closes the SQLite connection for the current thread.
        """
        if hasattr(self.local_storage, "connection"):
            self.local_storage.connection.close()
            del self.local_storage.connection

    def activate(self, connection):
        """
        Create the table if it does not exist.

        Parameters
        ----------
        connection : sqlite3.Connection
            The SQLite connection to use for executing the query.
        """
        try:
            cursor = connection.cursor()
            template = f"""
            CREATE TABLE IF NOT EXISTS {self.tablename} (
                key varchar(255) unique,
                value text,
                modification_date datetime
            );
            """
            cursor.execute(template)
            connection.commit()
        except sqlite3.Error as e:
            logger.error(f"Error while activating the database: {e}")

    @staticmethod
    def session(fnc):
        """
        Decorator to obtain an SQLite session (cursor) and manage transactions.

        Parameters
        ----------
        fnc : function
            The function to be decorated with session handling.

        Returns
        -------
        function
            The decorated function that provides a session for database operations.
        """

        def wrapper(self, *args, **kwargs):
            connection = self.get_connection()
            session = connection.cursor()
            try:
                result = fnc(self, session, *args, **kwargs)
                connection.commit()
                return result
            except sqlite3.Error as e:
                logger.error(f"Error during SQLite transaction: {e}")
                raise
            finally:
                session.close()

        return wrapper

    @session
    def put(self, session, key, value, savemode=False):
        """
        Insert or update a key-value pair in the specified table.

        Parameters
        ----------
        session : sqlite3.Cursor
            The cursor used to interact with the database.

        key : str
            The key to be inserted or updated.

        value : str
            The value associated with the key.

        savemode : bool, optional
            If True, the old value associated with the key will be returned (default is False).

        Returns
        -------
        str or None
            The old value if savemode is enabled, None otherwise.
        """
        logger.debug(f"Executing put with key: {key}, value: {value}")
        if savemode:
            old_value = self.get(key)
            logger.debug(f"Old value retrieved: {old_value}")
        session.execute(
            f"REPLACE INTO {self.tablename} (key, value, modification_date) VALUES (?, ?, CURRENT_TIMESTAMP)",
            (key, value),
        )
        if savemode:
            return old_value

    @session
    def get_all(self, session: sqlite3.Cursor):
        """
        Retrieve all key-value pairs from the specified table.

        Parameters
        ----------
        session : sqlite3.Cursor
            The cursor used to interact with the database.

        Returns
        -------
        dict
            A dictionary containing all key-value pairs from the table.
        """
        result = {}
        query = session.execute(f"SELECT key, value FROM {self.tablename}")
        data = query.fetchall()

        if data is None:
            return None

        for key, value in data:
            result[key] = value

        return result

    @session
    def get(self, session: sqlite3.Cursor, key: str):
        """
        Retrieve the value associated with the given key from the specified table.

        Parameters
        ----------
        session : sqlite3.Cursor
            The cursor used to interact with the database.

        key : str
            The key whose associated value is to be retrieved.

        Returns
        -------
        str or None
            The value associated with the key, or None if not found.
        """
        try:
            query = session.execute(
                f"SELECT value FROM {self.tablename} WHERE key = ?", (key,)
            )
            result = query.fetchone()
            if result is None:
                logger.error(f"No value found for key: {key}")
                return None
            return result[0]
        except sqlite3.Error as e:
            logger.error(f"Error while retrieving value for key {key}: {e}")
            return None

    @session
    def delete(self, session: sqlite3.Cursor, key: str):
        """
        Delete the key-value pair associated with the given key from the specified table.

        Parameters
        ----------
        session : sqlite3.Cursor
            The cursor used to interact with the database.

        key : str
            The key of the entry to be deleted.

        Returns
        -------
        bool
            True if the entry was deleted, False if the key does not exist.
        """
        try:
            query = session.execute(
                f"DELETE FROM {self.tablename} WHERE key = ?", (key,)
            )
            if query.rowcount == 0:
                logger.error(f"No entry found to delete for key: {key}")
                return False
            logger.debug(f"Entry deleted for key: {key}")
            return True
        except sqlite3.Error as e:
            logger.error(f"Error while deleting entry for key {key}: {e}")
            return False

    @session
    def clean(self, session, number: int, epoch: str):
        """
        Deletes records from the table that are older than the specified time difference.

        Parameters
        ----------
        session : sqlite3.Cursor
            The cursor used to manipulate the data in the database.

        number : int
            The 'quantity' of time used for the time difference.

        epoch : str
            The unit of time for the time difference. It can be one of the following:
            - 'years'
            - 'months'
            - 'days'
            - 'hours'
            - 'minutes'
            - 'seconds'
        """
        epochs = ["years", "months", "days", "hours", "minutes", "seconds"]
        if epoch not in epochs:
            logger.error(f"Invalid epoch: {epoch}. Must be one of {epochs}.")
            return

        try:
            number = abs(number)
            timediff = f"-{number} {epoch}"
            session.execute(
                f"DELETE FROM {self.tablename} WHERE modification_date < DATETIME('now', ?)",
                (timediff,),
            )
            logger.debug(
                f"Records older than {number} {epoch} have been deleted from {self.tablename}."
            )
        except sqlite3.Error as e:
            logger.error(f"Error during the clean operation: {e}")

    def __del__(self):
        self.close()
