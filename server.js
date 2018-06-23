var express = require('express');
var morgan = require('morgan');

var app = express();

//Middleware
app.use(morgan('dev')); //Log all the request the user logs

app.get('/', function(req, res){
    var name = "Batman";
    res.json("My name is " + name);

})
app.get('/catname', function(req, res){

    res.json("Batman");

})




app.listen(3000, function(err){
    if(err) throw err;
    console.log("Server is Running on port 3000");
});