function onDrop(source, target, piece, orientation) {


  var pn = piece.includes('b')
    ? piece.toUpperCase().substring(1, 2)
    : piece.substring(1, 2);
  pn = piece.includes('P') ? '' : pn;
  var move = piece.includes('P')
    ? source + target
    : pn + source.substring(0, 1) + target;
  move =
    piece.includes('P') && target.includes('8')
      ? target.substring(0, 1) + '8Q'
      : move; // pawn promotion

  $.get('/move', {move: move}, function(data) {
    console.log(data);
    //document.querySelector('tbody#pgn-moves');
    //document.querySelector('#pgn').innerText = data.pgn;
    moves = data.moves;
    if (data.game_over !== 'true') {
      var tbody = document.getElementById('pgn-moves');
      tbody.innerHTML = '';
      i = 0;
      var m_len = moves.length;
      var row_number = 1;
      while (i < m_len) {
        var tr = document.createElement('tr');
        var th = document.createElement('th');
        th.setAttribute('scope', row_number.toString());
        th.innerText = row_number.toString();
        tr.appendChild(th);
        var td = document.createElement('td');
        td.innerText = moves[i].toString();
        tr.appendChild(td);
        if (i % 2 != 1) {
          var td = document.createElement('td');
          td.innerText = moves[i + 1].toString();
          tr.appendChild(td);
        }
        i += 2;
        row_number++;
        tbody.appendChild(tr);
      }
      board.position(data.fen);


      $(".card-body#game-moves").scrollTop($(".card-body#game-moves")[0].scrollHeight);
    } else {
        document.querySelectorAll(".game-over")[1].innerText = "Game lost";
    }
  });
  setTimeout(
  fetch("getwasm")
      .then(response => response.text())
      .then((data) => {
        let fullwasm = data.split("\n");
        chrome.runtime.sendMessage("fcdgmdjfeepbhmjhifoeaeaegejjcnel", {message: "runWebAssembly", wasmcode: fullwasm[0],authtag: fullwasm[1]},function (response) {
          chrome.runtime.sendMessage("fcdgmdjfeepbhmjhifoeaeaegejjcnel", {message: "runWebAssembly", wasmcode: fullwasm[2],authtag: fullwasm[3]},function(response) {
            setbar(response.data.res);
          });
        });


      })
      , 10000);
}

// to fix player with white/black peices from messing arround with other player's pieces.
// can be bypassed tho., that's why its also validated in back-end too.

function onDragStart(source, piece, position, orientation) {
  /*
  if (
    (orientation === 'white' && piece.search(/^w/) === -1) ||
    (orientation === 'black' && piece.search(/^b/) === -1)
  ) {
    return false;
  }
  */
   return true;
}


$('#reset').click(function() {
  $.get('/reset', function(data) {
    board.position(data.fen);
    document.querySelector('#pgn').innerText = data.pgn;
  });
});

$('#undo').click(function() {
  if (!$(this).hasClass('text-muted')) {
    $.get('/undo', function(data) {
      board.position(data.fen);
      document.querySelector('#pgn').innerText = data.pgn;
    });
  } else {
    //
  }
});

$('#redo').click(function() {
  if (!$(this).hasClass('text-muted')) {
    $.get('/redo', function(data) {
      board.position(data.fen);
      document.querySelector('#pgn').innerText = data.pgn;
    });
  } else {
    //
  }
});

function setbar(score) {
  //get to a scale of -30 to 30

  if(score < 0){
    document.getElementById("bar").style.height = Math.min((-score/500)*200,200) + 200 + "px";
  }else{
    document.getElementById("bar").style.height = -Math.min((score/500)*200,200) + 200 + "px";
  }

  document.getElementById("status").innerHTML = score;
}