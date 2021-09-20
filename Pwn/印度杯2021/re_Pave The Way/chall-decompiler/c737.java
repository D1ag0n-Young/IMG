class c737 {
   public static void main(String[] var0) throws Exception {
      System.out.print("Paving your way.");
      pave("");
   }

   public static void pave(String var0) throws Exception {
      var0 = var0 + "5";
      System.out.print(".");
      Thread.sleep(3600000L);
      c159.pave(var0);
   }
}
