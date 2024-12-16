const express=require("express")
const app=express()
app.use(express.json())
const cors=require("cors")
app.use(cors({
    origin: "http://localhost:3000",
    credentials:true
}))

app.use(express.urlencoded({ extended: true }));
const  ContactController  = require("../controllers/ContactController");

const router=express.Router()
router.get("/",ContactController.ContactController)
router.get("/fetchcontact",ContactController.getAllContact)
router.post("/addcontact",ContactController.AddContact)
router.delete("/deletecontact/:id",ContactController.deleteContact)
router.put("/editcontact/:id",ContactController.editContact)
router.get("/contactbydate",ContactController.getContactByDate)

module.exports=router;