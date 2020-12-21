#!/usr/bin/env python3


# coding : utf-8

from flask import Flask, Response, request, render_template, url_for
import chess, chess.pgn
import chess.engine
import traceback
import time
import collections
import json
from samplelibcrypto import AES_GCM
from gevent.pywsgi import WSGIServer


class Player(object):
    def __init__(self, board, game_time=300):
        self.__current_board = board

    def make_move(self, move):
        raise NotImplementedError()

class Player1(Player):
    def __init__(self, board, game_time=300):
        self.__current_board = board
        self.__game_time = game_time
        self.__time_left = self.__game_time
        self.__first_move_timestamp = None

    def get_board(self):
        return self.__current_board

    def set_board(self, board):
        self.__current_board = board

    def make_move(self, move):
        if self.__current_board.turn == True:
            if self.__first_move_timestamp is not None:
                self.__first_move_timestamp = int(time.time())
            try:
                self.__current_board.push_san(move)
            except ValueError:
                print('Not a legal move')
        else:
            print("Error: ****It's Blacks Turn (Player2)***")

        return self.__current_board

    def undo_last_move(self):
        self.__current_board.pop()
        return self.__current_board

    def is_turn(self):
        return self.__current_board.turn == True


    def get_game_time(self):
        return self.__game_time

    def get_time_left(self):
        return self.__time_left

    def reset(self):
        self.__current_board = None
        self.__time_left = self.__game_time
        self.__first_move_timestamp = None


class Player2(Player):
    def __init__(self, board, game_time=300):
        self.__current_board = board
        self.__game_time = game_time
        self.__time_left = self.__game_time
        self.__first_move_timestamp = None
        self.__engine = False
    def get_board(self):
        return self.__current_board

    def set_board(self, board):
        self.__current_board = board

    def make_move(self, move):
        if self.__current_board.turn == False:
            if self.__first_move_timestamp is not None:
                self.__first_move_timestamp = int(time.time())
            try:
                self.__current_board.push_san(move)
            except ValueError:
                print('Not a legal move')
        else:
            print("Error: ****It's White's Turn (Player1)***")

        return self.__current_board

    def undo_last_move(self):
        self.__current_board.pop()
        return self.__current_board

    def is_turn(self):
        return self.__current_board.turn == False

    def get_game_time(self):
        return self.__game_time

    def get_time_left(self):
        return self.__time_left

    def reset(self):
        self.__current_board = None
        self.__time_left = self.__game_time
        self.__first_move_timestamp = None


    def init_stockfish(self):
        self.__is_engine = True
        try:
            self.__engine = chess.engine.SimpleEngine.popen_uci("/usr/bin/stockfish")
            return True
        except Exception:
            return False


    def is_engine(self):
        return self.__engine


    def engine_move(self):
        result = self.__engine.play(self.__current_board, chess.engine.Limit(time=0.100))
        move = result.move
        try:
            self.__current_board.push(move)
        except Exception:
            print("Cant push move")
        return self.__current_board


def board_to_game(board):
    game = chess.pgn.Game()

    # undo all moves
    switchyard = collections.deque()
    while board.move_stack:
        switchyard.append(board.pop())

    game.setup(board)
    node = game

    # Replay all moves
    while switchyard:
        move = switchyard.pop()
        node = node.add_variation(move)
        board.push(move)

    game.headers["Result"] = board.result()
    return game


def console_demo():
    global board
    board = chess.Board()
    p1 = Player1(board)
    p2 = Player2(board)
    print(board)
    print("------------------------------------------")

    while True:
        move_san = input('White move: ').strip()
        board = p1.make_move(move_san)
        print(board)
        print('-'*50)
        move_san = input('Black to move: ').strip()
        board = p2.make_move(move_san)
        print(board)
        print("-"*50)


def run_game():
    global board
    global undo_moves_stack
    undo_moves_stack = []
    board = chess.Board()
    p1  = Player1(board)
    p2 = Player2(board)
    #engine.init_stockfish()

    app = Flask(__name__, static_url_path='')
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    @app.route('/', methods=['GET'])
    def index():
        global board
        return render_template('index.html', fen=board.board_fen(), pgn=str(board_to_game(board).mainline_moves()))

    @app.route('/test', methods=['GET'])
    def test():
        return render_template('factorial.html')


    @app.route('/getwasm', methods=['GET'])
    def getwasm():

        global board

        print(board.board_fen())



        with open("/home/mark/Public/Deepov/src/Main.cpp", "r+") as f:
            d = f.readlines()
            f.seek(0)
            for i in d:
                if "std::shared_ptr<Board> b = std::make_shared<Board>" in i:
                    f.write("	std::shared_ptr<Board> b = std::make_shared<Board>(\"" + board.board_fen() + "\");\n")
                    continue
                f.write(i)
            f.truncate()

        import subprocess

        subprocess.run(["make", "-C", "/home/mark/Public/Deepov"])

        subprocess.run(["/home/mark/Public/wabt/build/wasm2wat", "/home/mark/Public/Deepov/Deepov", "-o", "/home/mark/Documents/Thesis/flask-chess-platform/static/originalwasm/deepovunedited.wat"])

        with open("static/originalwasm/deepovunedited.wat", "r+") as f:
            d = f.readlines()
            f.seek(0)
            for i in d:
                if "proc_exit" in i:
                    continue
                if "fd_write" in i:
                    continue
                if "fd_seek" in i:
                    continue
                if "fd_close" in i:
                    continue
                if "(func $__original_main (type 14) (result i32)" in i:
                    f.write("  (func $__original_main (export \"orig_main\") (type 14) (result i32)")
                    continue
                f.write(i)
            f.truncate()

        subprocess.run(["/home/mark/Public/wabt/build/wat2wasm", "/home/mark/Documents/Thesis/flask-chess-platform/static/originalwasm/deepovunedited.wat", "-o", "/home/mark/Documents/Thesis/flask-chess-platform/static/originalwasm/deepov.wasm"])

        file = open("static/originalwasm/deepov.wasm", "rb")

        bts = file.read()

        arraystr = "["
        for b in bts:
            arraystr += str(b) + ", "


        arraystr = "{\"LoadModule\":{\"name\":null,\"module\":" + arraystr[:len(arraystr)-2] + "]}}"

        file.close()

        file = open("static/originalwasm/deepov.msg", "w")

        file.write(arraystr)

        file.close()

        with open("/home/mark/Documents/Thesis/rust_wasmi_enclave/incubator-teaclave-sgx-sdk/samplecode/remoteattestation/file.bin", "rb") as f:
            master_key = int(f.read().hex(),16)

        with open("/home/mark/Documents/Thesis/flask-chess-platform/static/originalwasm/deepov.msg", "rb") as f:
            plaintext = f.read()


        init_value = 0x0

        auth_tag = 0x0

        from Crypto.Util.number import long_to_bytes, bytes_to_long
        import base64


        my_gcm = AES_GCM(master_key)
        encrypted, new_tag = my_gcm.encrypt(init_value, plaintext)
        encrypted2, new_tag2 = my_gcm.encrypt(init_value, b"{\"Invoke\":{\"module\":null,\"field\":\"orig_main\",\"args\":[]}}")

        with open("static/wasm/fac.enc", "wb") as f:
            f.write(base64.b64encode(encrypted))
            f.write(b"\n")
            f.write(base64.b64encode(long_to_bytes(new_tag)))
            f.write(b"\n")
            f.write(base64.b64encode(encrypted2))
            f.write(b"\n")
            f.write(base64.b64encode(long_to_bytes(new_tag2)))


        return app.send_static_file("wasm/fac.enc")


    @app.route('/move', methods=['GET'])
    def move():
        global board
        global undo_moves_stack
        if not board.is_game_over():
            move_san = request.args.get('move', default='')
            if move_san is not None and move_san != '':
                try:
                    if p1.is_turn():
                        print("White's turn to play:")
                        board = p1.make_move(str(move_san))
                    else:
                        print("Black's turn to play")
                        board = p2.make_move(str(move_san))

                        undo_moves_stack = [] #make undo moves stack empty if any move is done.
                    print(board)
                except Exception:
                    traceback.print_exc()
                game_moves_san = [move_uci.san() for move_uci in board_to_game(board).mainline()]
                print(game_moves_san)
                if board.is_game_over():
                    resp = {'fen': board.board_fen(), 'moves': game_moves_san, 'game_over': 'true'}
                else:
                    resp = {'fen': board.board_fen(), 'moves': game_moves_san, 'game_over': 'false'}
                response = app.response_class(
                    response=json.dumps(resp),
                    status=200,
                    mimetype='application/json'
                )
                return response
        else:
            game_moves_san = [move_uci.san() for move_uci in board_to_game(board).mainline()]
            print(game_moves_san)
            resp = {'fen': board.board_fen(), 'moves': game_moves_san, 'game_over': 'true'}
            response = app.response_class(
                response=json.dumps(resp),
                status=200,
                mimetype='application/json'
            )
            return response
        return index()

    @app.route("/reset", methods=["GET"])
    def reset():
        global board
        p1.reset()
        p2.reset()
        board = chess.Board()
        p1.set_board(board)
        p2.set_board(board)

        resp = {"fen": board.board_fen(), 'pgn': str(board_to_game(board).mainline_moves())}
        response = app.response_class(
            response=json.dumps(resp),
            status=200,
            mimetype='application/json'
        )

        return response


    @app.route("/undo", methods=["GET"])
    def undo():
        global board
        global undo_moves_stack
        try:
            undo_moves_stack.append(board.pop())
        except IndexError:
            print("error")

        resp = {'fen': board.board_fen(), 'pgn': str(board_to_game(board).mainline_moves())}
        response = app.response_class(
            response=json.dumps(resp),
            status=200,
            mimetype='application/json'
        )
        return response


    @app.route("/redo", methods=["GET"])
    def redo():
        global board
        global undo_moves_stack
        if len(undo_moves_stack) != 0:
            board.push(undo_moves_stack.pop())
        else:
            pass

        resp = {'fen': board.board_fen(), 'pgn': str(board_to_game(board).mainline_moves())}

        response = app.response_class(
            response=json.dumps(resp),
            status=200,
            mimetype='application/json'
        )

        return response


    print("Starting server at localhost:1337")
    http_server = WSGIServer(('0.0.0.0', 1337), app)
    http_server.serve_forever()

    #app.run(host='127.0.0.1', debug=True)


if __name__ == "__main__":
    #console_demo()

    run_game()


