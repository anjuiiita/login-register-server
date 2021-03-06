var express = require('express');
var router = express.Router();
const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const bcrypt = require('bcrypt');
const saltRounds = 10;

const db = mysql.createPool({
  host: 'localhost', // HOST NAME
  user: 'root', // USER NAME
  database: 'thor', // DATABASE NAME
  password: '' // DATABASE PASSWORD
});

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.post('/register', function(req, res) {
  const first_name = req.body.firstName;
  const last_name = req.body.lastName;
  const email = req.body.email;
  const password = req.body.password;

  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.log(err);
    }
    db.query(
      "INSERT INTO user_details (first_name, last_name, email, password) VALUES (?,?,?,?)",
      [first_name, last_name, email, hash],
      (err, result) => {
        if (err) {
          console.log(err);
          res.send({message: err.sqlMessage, user: result[0].first_name});
        } else {
          console.log(result);
          res.send({message: "Success"});
        }
      }
    );
  })

  
});



const verifyJWT = (req, res, next) => {
  const token = req.headers["x-access-token"];

  if (!token) {
    res.token("Send a token!");
  } else {
      jwt.verify(token, "jwtSecret", (err, decoded) => {
        if (err) {
          res.json({auth: false, message: "Authentication Failed!"});
        } else {
          req.userId = decoded.id;
          next();
        }
    })
  }
}

router.get('/isUserAuth', verifyJWT, function(req, res, next) {
  console.log(req.session)
  if (req.session.user) {
    res.send({loggedIn: true, user: req.session.user});
  } else {
    res.send({loggedIn: false});
  }
});

router.get('/getCategories', function(req, res) {
  db.query(
    "SELECT * from category_identification",
    (err, result) => {
      if (err) {
        console.log(err);
        res.send({message: "Error Occured!"});
      } else {
        res.json({result})
      }
    });
});

router.get('/getOrg', function(req, res) {
  db.query(
    "SELECT org_name from organization",
    (err, result) => {
      if (err) {
        console.log(err);
        res.send({message: "Error Occured!"});
      } else {
        res.json({result})
      }
    });
});

router.post('/insertCategory', function(req, res) {
  category = req.body.category;
  db.query(
    "insert into category (category, subcategory) values (?, ?)", category, category,
    (err, result) => {
      if (err) {
        console.log(err);
        res.send({message: "Error Occured!"});
      } else {
        res.json({result})
      }
    });
});

// router.get('/isUserAuth', verifyJWT, (req, res) => {
//   res.send("you are authenticated!");
// });

router.post('/login', function(req, res) {
  const email = req.body.email;
  const password = req.body.password;
  db.query(
    "SELECT * from user_details where email = ?",
    email,
    (err, result) => {
      if (err) {
        console.log(err);
        res.send({message: "Error Occured!"});
      } else {
        console.log(result)
        if (result.length > 0) {
          bcrypt.compare(password, result[0].password, (error, response) => {
            if (response) {
              const id = result[0].email;
              const token = jwt.sign({id}, "jwtSecret", {
                expiresIn: 3000,
              })
              req.session.user = result;
              res.json({ auth: true, token: token, result: result })
            } else {
              res.send({auth: false, message: "Wrong username/password!"});
            }
          })
        } else {
          res.send({auth: false, message: "No user found"});
        }
      }
    }
  );
});


router.post('/getCardDetails', function(req, res) {
  category = req.body.category;
  sub_category = req.body.sub_category;
  ss_category = req.body.ss_category;
  level = req.body.level;
  db.query(
    "Select category_id from category_identification where (category=? OR ? IS NULL) and (sub_category=? OR ? IS NULL) and (ss_category=? OR ? IS NULL) and (level=? OR ? IS NULL)", 
    [category, category, sub_category, sub_category, ss_category, ss_category, level, level],
    (err, result) => {
      if (err) {
        console.log(err);
        res.send({message: "Error Occured!"});
      }
      table = category.split(' ').join('_');
      query = 'Select curricula_id from ' + table;
      if (result.length > 0) {
        query += ' where ';
      }
      for(let i = 0; i < result.length; i++) { 
        query += result[i].category_id + ' IS NOT NULL'
        if (i != result.length - 1) {
          query += ' OR '
        }
      }
        
      db.query(
        query,
        (err, result1) => {
          if (err) {
            console.log(err);
            res.send({message: "Error Occured!"});
          }
          curricula_id_list = []
          for (var key in result1) {
              curricula_id_list.push(result1[key].curricula_id);
          }

          db.query(
            "Select * from curricula where curricula_id IN ?", [[curricula_id_list]],
            (err, result2) => {
              if (err) {
                res.send({message: "Error Occured!"});
              } 
              res.send(result2);
            }
          )
        }
      )
    }
  )
})

module.exports = router;
