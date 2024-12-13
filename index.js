const express = require('express')
const app = express()
const port = 1234
const db = require('../DioSync-Backend/db'); // Import the database connection
const cors = require('cors'); 

app.use(express.json())
app.use(cors({
  origin: 'http://localhost:3000', // Replace with your frontend's URL
  methods: ['GET', 'POST'], // Specify allowed methods
  allowedHeaders: ['Content-Type', 'Authorization'], // Specify allowed headers
}));
app.use('/accounts', require("./routes/auth"))
app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})