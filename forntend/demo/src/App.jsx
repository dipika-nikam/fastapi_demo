import React, { useEffect, useState } from "react";

const App=() => {
  const [message, setMessage] = useState("");
  const getwelcome = async ()=>{
    const requestOptions ={
      method : "GET",
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
    };
    const response = await fetch("http://127.0.0.1:8000/api",{ mode: 'cors' }, requestOptions);
    const data = await response.json();
    if (!response.ok){
      console.log("Somthing went worng");
    } else{
      setMessage(data.message);
    }
  }
  useEffect(()=>{
    getwelcome();

  },[])
  return (
    <div>
      <h1> {message} </h1>
    </div>
  );
}

export default App;
