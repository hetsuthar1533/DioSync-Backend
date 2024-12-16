
const db = require("./db")
const express = require("express")
const app = express()
app.use(express.json())
const cors = require("cors")
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true
}))

app.use(express.urlencoded({ extended: true }));
const Itemrouter = require("./routes/ItemRoute")
const ContactRouter=require("./routes/ContactRoute")
const DestinationRouter=require("./routes/DestinationRoute")
app.use(express.urlencoded({ extended: true }));

app.use("/",Itemrouter)
app.use("/",ContactRouter)
app.use("/",DestinationRouter)


app.use('/accounts', require("./routes/auth"))

const server = app.listen(1234, () => {
  console.log("server is running on port 1234")
})