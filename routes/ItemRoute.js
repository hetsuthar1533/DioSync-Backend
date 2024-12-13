const express=require("express")
const app=express()
app.use(express.json())
const cors=require("cors")
app.use(cors({
    origin: "http://localhost:3000",
    credentials:true
}))

app.use(express.urlencoded({ extended: true }));
const  ItemController  = require("../controllers/ItemController");

const router=express.Router()
router.get("/",ItemController.ItemController)
router.get("/fetchItem",ItemController.getAllItem)
router.post("/addItem",ItemController.AddItem)
router.delete("/deleteItem/:id",ItemController.deleteItem)
router.put("/editItem/:id",ItemController.editItem)

module.exports=router;