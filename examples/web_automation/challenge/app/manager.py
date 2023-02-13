from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Float
from random import randint

engine = create_engine('sqlite:////tmp/ctf.db')
sess = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))

Base = declarative_base()
Base.query = sess.query_property()


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True, unique=True)
    username = Column(String(10))
    password = Column(String(10))

    def __init__(self, username, password):
        self.username = username
        self.password = password


def seed():
    Base.metadata.create_all(bind=engine)

    users = [
        User("pwntest", "foobar")
    ]

    for user in users:
        sess.add(user)

    sess.commit()
