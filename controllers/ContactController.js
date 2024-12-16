const express=require("express")
const app=express()
app.use(express.json())
const cors=require("cors")
app.use(cors({
    origin: "http://localhost:3000",
    credentials:true
}))


app.use(express.urlencoded({ extended: true }));

const db=require("../db");
 const ContactController=(req,res)=>{
    res.status(200).send("sent success")
}
const AddContact = async (req, res) => {
    try {
         const {ItemName,BrandName,Category,Subcategory,unitSize,status} = req.body;

console.log(req.body);

            await db.promise().query(
                "INSERT INTO item ( ItemName,BrandName,Category,Subcategory,unitSize,status) VALUES (?, ?, ?, ?,?,?)",
                [ ItemName,BrandName,Category,Subcategory,unitSize,status ]
            );

            res.status(200).json({
                message: "order placed successfully",
                data: {
                    ItemName,BrandName,Category,Subcategory,unitSize}
            });
        }
     catch (err) {
        console.error(err);
        res.status(500).send("Internal server error");
    }
};

const getAllContact = async (req, res) => {
    try {
        const [item] = await db.promise().query("SELECT * FROM item");

       

        res.status(200).json({
            success: true,
            message: "item fetched successfully",
            data: item,
        });
    } catch (error) {
        console.error("Failed to fetch item", error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch item",
        });
    }
};
const deleteContact=async(req,res)=>{
    try{
        console.log("hi i am delete item");
        const id=req.params;
        console.log(id);
        console.log("hi i am delete item");
        await db.promise().query("delete from item where itemId=?",[id.id])
        
        res.status(200).send("delete success")
    }
    catch(error){
        res.status(500).json({
            success: false,
            message: "Failed to fetch item",
        });
    }
    

    
}
const editContact=async(req,res)=>{
    try{
        console.log("hi i am edit item");
        console.log(req.body);
        
        const {ItemName,BrandName,Category,Subcategory,unitSize,status} = req.body;
        const id=req.params.id;
        console.log(id);
        
        if(ItemName)
{         await db.promise().query("update item set ItemName=? where itemId=?  ",[ItemName,id])
console.log("updated");

}
if(BrandName)
    console.log(BrandName);
    
    {         await db.promise().query("update item set BrandName=? where itemId=?  ",[BrandName,id])
    console.log("updated");
    

    }
    if(Category)
        {         await db.promise().query("update item set Category=? where itemId=?  ",[Category,id])
        console.log("updated");
        
        }
        if(Subcategory)
        {
            await db.promise().query("update item set Subcategory=? where itemId=?  ",[Subcategory,id])
            console.log("updated");

        }
        if(unitSize)
        {
            await db.promise().query("update item set unitSize=? where itemId=?  ",[unitSize,id])
            console.log("updated");

        }
        if(status)
            {
                await db.promise().query("update item set status=? where itemId=?  ",[status,id])
                console.log("updated status");
    
            }
  
        res.status(200).send("Updated successfully")


        }


 
    catch(error)
    {
res.send(error)
    }
}

module.exports = { 
    AddContact, 
    getAllContact,
    deleteContact,
    editContact,
    ContactController
  };
  