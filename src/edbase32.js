//LICENSE: MIT to Kahiro Koo
// https://github.com/KahiroKoo/edBase32
// Modified by Kristian Rekstad: removed decode; use buffer as input.

//encode base32 in RFC 3548
const base32 = (function(){
  this.encode = encode;
  const charJson = {
      '0' : 'A',
      '1' : 'B',
      '2' : 'C',
      '3' : 'D',
      '4' : 'E',
      '5' : 'F',
      '6' : 'G',
      '7' : 'H',
      '8' : 'I',
      '9' : 'J',
      '10' : 'K',
      '11' : 'L',
      '12' : 'M',
      '13' : 'N',
      '14' : 'O',
      '15' : 'P',
      '16' : 'Q',
      '17' : 'R',
      '18' : 'S',
      '19' : 'T',
      '20' : 'U',
      '21' : 'V',
      '22' : 'W',
      '23' : 'X',
      '24' : 'Y',
      '25' : 'Z',
      '26' : '2',
      '27' : '3',
      '28' : '4',
      '29' : '5',
      '30' : '6',
      '31' : '7'
  }

  /**
   * 
   * @param {Uint8Array} input 
   */
  function encode(input){
      if(typeof input == 'undefined' || input == null){
          return null;
      }
      var aAscii2 = [];
      for(const ascii of input){
          var ascii2 = ascii.toString(2);
          var gap = 8 - ascii2.length;
          var zeros = '';
          for(var i = 0; i < gap; i++){
              zeros = '0' + zeros;
          }
          ascii2 = zeros + ascii2;
          
          aAscii2.push(ascii2);
      }
      
      var source = aAscii2.join('');
      
      var eArr = [];
      for(var i = 0; i < source.length; i += 5){
          var s5 = source.substring(i, i + 5);
          if(s5.length < 5){
              var gap = 5 - s5.length;
              var zeros = '';
              for(var gi = 0; gi < gap; gi++){
                  zeros += '0';
              }
              s5 += zeros;
          }
          
          var eInt = parseInt(s5, 2)
          
          eArr.push(charJson[eInt]);
      }
      if(eArr.length % 8 != 0){
          var gap = 8 - (eArr.length % 8);
          for(var i = 0; i < gap; i++){
              eArr.push('=');
          }
      }
      var eStr = eArr.join('');
      
      return eStr;
  }

return this;
})();

module.exports = {
  encode: base32.encode,
};