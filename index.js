const db=require("./db")
const express=require("express")
const app=express()
app.use(express.json())
const cors=require("cors")
app.use(cors({
    origin: "http://localhost:3000",
    credentials:true
}))

app.use(express.urlencoded({ extended: true }));
const router = require("./routes/ItemRoute")


app.use(express.urlencoded({ extended: true }));
app.use("/",router)
const server=app.listen(1234,()=>{
    console.log("server is running on port 1234")
})
