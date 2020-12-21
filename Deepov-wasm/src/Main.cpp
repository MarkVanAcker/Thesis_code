/*
	Deepov, a UCI chess playing engine.

	Copyright (c) 20014-2016 Romain Goussault, Navid Hedjazian

    Deepov is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Deepov is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Deepov.  If not, see <http://www.gnu.org/licenses/>.
*/


#include "Types.hpp"
#include "Eval.hpp"
#include "Search.hpp"
#include "Board.hpp"
#include "MoveGen.hpp"
#include "Move.hpp"
#include "MagicMoves.hpp"
#include "Utils.hpp"
#include "TT.hpp"

//#define PERFORMANCE_TEST


int main_evaluate(){
	std::shared_ptr<Board> b = std::make_shared<Board>("rnbqkbnr/ppppp2p/5p2/6p1/3PP3/8/PPP2PPP/RNBQKBNR");
	globalTT.init_TT_size(256);
	// init Pawn hashtable
	Pawn::initPawnTable();
	Search mySearch = Search(b);
	//std::cout << mySearch.negaMaxRoot(1) << std::endl;
	return mySearch.negaMaxRoot(1);
}

int main() {

    // Init engine parameters
	MagicMoves::initmagicmoves();
	Tables::init();
	ZK::initZobristKeys();
	return main_evaluate();
	return 0;
}
